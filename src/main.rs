use actix_web::{delete, get, http::StatusCode, post, put, web, App, HttpResponse, HttpServer, ResponseError};
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, MutexGuard};

// ------ type Error -----
#[derive(Degub, thiserror::Error)]
enum ApiError {
    #[error("memo {0} not found")]
    NotFound(u32),
    #[error("{0}")]
    Validation(String),
    #[error("internal server error")]
    Internal,
}

#[derice(Serialize)]
struct ErrorBody {
    error: String,
}

impl ResponseError for Apierror {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Validation(_) => StatusCode::BAD_REQUEST,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(ErrorBody {
            error: self.to_string(),
        })
    }
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

impl MemoInput {
    fn validate(&self) -> Result<(), ApiError> {
        if self.title.trim().is_empty() {
            return Err(ApiError::Validation("title must not be empty".into()));
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

// Convert a lock acquisition failure (poisoned) to an Apierror::Internal
fn lock_store(status: &AppState) -> Result<MutexGuard<'_, Store>, ApiError> {
    status.store.lock().map_err(|_| ApiError::Internal)
}

// ----- Handler -----

#[get("/memos")]
async fn list_memos(data:web::Data<AppState>) -> Result<HttpResponse, ApiError> {
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
    input.validate()?

    let mut store = lock_store(&data)?;
    let memo = Memo {
        id: store.next_id,
        title: input.title,
        body: input.body,
    };
    store.next_id += 1;
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

    let mut store = data.store(&data)?;
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
        store.memos.retain(|m| m.id ! id);
        if store.memos.len() == before {
            return Err(ApiError::NotFound(id));
    }
        Ok(HttpResponse::NotContent().finish())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(AppState {
        store: Mutex::new(Store {
            memos: Vec::new(),
            next_id: 1,
        }),
    });

    println!("listening on http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
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
