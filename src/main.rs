use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, ResponseError, delete,
    error::{JsonPayloadError, PathError},
    get,
    http::StatusCode,
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::{from_fn, DefaultHeaders, Next},
    post, put, web,
};
use subtle::ConstantTimeEq;
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, MutexGuard};
use actix_governor::{Governor, GovernorConfigBuilder};

const MAX_TITLE_LEN: usize = 100;
const MAX_BODY_LEN: usize = 2000;
const MAX_MEMOS: usize = 1000;

// ------ type Error -----
#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("memo {0} not found")]
    NotFound(u32),
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    LimitReached(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("internal server error")]
    Internal,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Validation(_) => StatusCode::BAD_REQUEST,
            ApiError::LimitReached(_) => StatusCode::CONFLICT,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(ErrorBody {
            error: self.to_string(),
        })
    }
}

fn json_error_handle(err: JsonPayloadError, _req: &HttpRequest) -> actix_web::Error {
    eprintln!("json error: {err}"); // Details are recorded only in the error log
    ApiError::Validation("invalid JSON body".into()).into()
}

fn path_error_handler(err: PathError, _req: &HttpRequest) -> actix_web::Error {
    eprintln!("path error: {err}");
    ApiError::Validation("invalid path parameter".into()).into()
}
// ----- Model -----
#[derive(Serialize, Clone)]
struct Memo {
    id: u32,
    title: String,
    body: String,
}

#[derive(Deserialize)]
struct MemoInput {
    title: String,
    body: String,
}

fn contains_bad_control(s: &str, allow_whitespace: bool) -> bool {
    s.chars()
        .any(|c| c.is_control() && !(allow_whitespace && matches!(c, '\n' | '\r' | '\t')))
}
impl MemoInput {
    fn validate(&self) -> Result<(), ApiError> {
        let title = self.title.trim();
        if title.is_empty() {
            return Err(ApiError::Validation("title must not be empty".into()));
        }
        // count by the number of characters, not the number of bytes
        if title.chars().count() > MAX_TITLE_LEN {
            return Err(ApiError::Validation(format!(
                "title must be at most {MAX_TITLE_LEN} characters"
            )));
        }
        if self.body.chars().count() > MAX_BODY_LEN {
            return Err(ApiError::Validation(format!(
                "body must be at most {MAX_BODY_LEN} characters"
            )));
        }
        if contains_bad_control(&self.title, false) || contains_bad_control(&self.body, true) {
            return Err(ApiError::Validation(
                "control characters are not allowed".into(),
            ));
        }
        Ok(())
    }
}

struct Store {
    memos: Vec<Memo>,
    next_id: u32,
}

struct AppState {
    store: Mutex<Store>,
}

struct ApiKey {
    value: String,
}

// Convert a lock acquisition failure (poisoned) to an Apierror::Internal
fn lock_store(status: &AppState) -> Result<MutexGuard<'_, Store>, ApiError> {
    status.store.lock().map_err(|_| ApiError::Internal)
}

// Key retenion and authentication middleware
async fn api_key_auth(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let expected = match req.app_data::<web::Data<ApiKey>>() {
        Some(k) => k,
        None => return Ok(req.into_response(ApiError::Internal.error_response())),
    };

    let provided = req
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // 
    let ok: bool = provided.as_bytes().ct_eq(expected.value.as_bytes()).into();
    if !ok {
        return Ok(req.into_response(ApiError::Unauthorized.error_response()));
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}

// ----- Handler -----
#[get("/memos")]
async fn list_memos(data: web::Data<AppState>) -> Result<HttpResponse, ApiError> {
    let store = lock_store(&data)?;
    Ok(HttpResponse::Ok().json(&store.memos))
}

#[get("/memos/{id}")]
async fn get_memo(
    path: web::Path<u32>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let store = lock_store(&data)?;
    let memo = store
        .memos
        .iter()
        .find(|m| m.id == id)
        .ok_or(ApiError::NotFound(id))?;
    Ok(HttpResponse::Ok().json(memo))
}

#[post("/memos")]
async fn create_memo(
    input: web::Json<MemoInput>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let input = input.into_inner();
    input.validate()?;

    // Maximum Number of Records and Measures to Prevent ID Overflow
    let mut store = lock_store(&data)?;
    if store.memos.len() >= MAX_MEMOS {
        return Err(ApiError::LimitReached("memo limit reached".into()));
    }
    let id = store.next_id;
    store.next_id = id.checked_add(1).ok_or(ApiError::Internal)?;
    let memo = Memo {
        id,
        title: input.title,
        body: input.body,
    };
    store.memos.push(memo.clone());
    Ok(HttpResponse::Created().json(memo))
}

#[put("/memos/{id}")]
async fn update_memo(
    path: web::Path<u32>,
    input: web::Json<MemoInput>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let input = input.into_inner();
    input.validate()?;

    let mut store = lock_store(&data)?;
    let memo = store
        .memos
        .iter_mut()
        .find(|m| m.id == id)
        .ok_or(ApiError::NotFound(id))?;
    memo.title = input.title;
    memo.body = input.body;
    Ok(HttpResponse::Ok().json(&*memo))
}

#[delete("/memos/{id}")]
async fn delete_memo(
    path: web::Path<u32>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let mut store = lock_store(&data)?;
    let before = store.memos.len();
    store.memos.retain(|m| m.id != id);
    if store.memos.len() == before {
        return Err(ApiError::NotFound(id));
    }
    Ok(HttpResponse::NoContent().finish())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let governor_conf = GovernorConfigBuilder::default()
        .seconds_per_request(1)
        .burst_size(10)
        .finish()
        .expect("invalid governor config");

    let api_key = std::env::var("API_KEY").expect("API_KEY must be set");
    if api_key.len() < 32 {
        panic!("API_KEY must be at be least 32 charactes");
    }
    let api_key = web::Data::new(ApiKey{ value: api_key });

    let state = web::Data::new(AppState {
        store: Mutex::new(Store {
            memos: Vec::new(),
            next_id: 1,
        }),
    });

    println!("listening on http://127.0.0.1:8080");

    HttpServer::new(move || {
        let json_config = web::JsonConfig::default()
            .limit(4096)
            .error_handler(json_error_handle);
        let path_config = web::PathConfig::default().error_handler(path_error_handler);
        
        App::new()
            .app_data(state.clone())
            .app_data(api_key.clone())
            .app_data(json_config)
            .app_data(path_config)
            .wrap(from_fn(api_key_auth)) // The element wrapperd first is on the inside
            .wrap(
                DefaultHeaders::new()
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"))
                    .add(("Referrer-Policy", "no-referrer"))
                    .add(("Cache-Control", "no-store")),
                )
            .service(list_memos)
            .service(get_memo)
            .service(create_memo)
            .service(update_memo)
            .service(delete_memo)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
