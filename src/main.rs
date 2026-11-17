use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{
    App, HttpMessage, HttpRequest, HttpResponse, HttpServer, ResponseError,
    body::{BoxBody, MessageBody},
    delete,
    dev::{ServiceRequest, ServiceResponse},
    error::{JsonPayloadError, PathError},
    get,
    http::{StatusCode, header},
    middleware::{DefaultHeaders, Next, from_fn},
    post, put, web,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::BufReader,
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

// ===== Limits =====
const MAX_TITLE_LEN: usize = 100;
const MAX_BODY_LEN: usize = 2000;
const MAX_MEMOS_PER_USER: usize = 100;
const MAX_USERS: usize = 100;
const USERNAME_MIN: usize = 3;
const USERNAME_MAX: usize = 32;
const PASSWORD_MIN: usize = 12;
const PASSWORD_MAX: usize = 128;
const TOKEN_TTL_SECS: u64 = 3600;

// ===== Error type =====
#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("memo {0} not found")]
    NotFound(u32),
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    LimitReached(String),
    #[error("{0}")]
    Conflict(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid username or password")]
    InvalidCredentials,
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
            ApiError::LimitReached(_) | ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Unauthorized | ApiError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(ErrorBody {
            error: self.to_string(),
        })
    }
}

fn json_error_handler(err: JsonPayloadError, _req: &HttpRequest) -> actix_web::Error {
    eprintln!("json error: {err}"); // details go to the server log only
    ApiError::Validation("invalid JSON body".into()).into()
}

fn path_error_handler(err: PathError, _req: &HttpRequest) -> actix_web::Error {
    eprintln!("path error: {err}");
    ApiError::Validation("invalid path parameter".into()).into()
}

// ===== Models =====
#[derive(Serialize, Clone)]
struct Memo {
    id: u32,
    #[serde(skip_serializing)]
    owner_id: u32,
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

#[derive(Clone)]
struct User {
    id: u32,
    username: String,
    password_hash: String,
}

struct UserStore {
    users: Vec<User>,
    next_id: u32,
}

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    fn validate(&self) -> Result<(), ApiError> {
        let name_len = self.username.chars().count();
        let name_ok = (USERNAME_MIN..=USERNAME_MAX).contains(&name_len)
            && self
                .username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !name_ok {
            return Err(ApiError::Validation(format!(
                "username must be {USERNAME_MIN}-{USERNAME_MAX} characters: letters, digits, '_' or '-'"
            )));
        }
        let pw_len = self.password.chars().count();
        if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&pw_len) {
            return Err(ApiError::Validation(format!(
                "password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters"
            )));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct RegisterResponse {
    id: u32,
    username: String,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
    token_type: &'static str,
    expires_in: u64,
}

// ===== State =====
struct Store {
    memos: Vec<Memo>,
    next_id: u32,
}

struct AppState {
    store: Mutex<Store>,
    users: Mutex<UserStore>,
}

fn lock_store(state: &AppState) -> Result<MutexGuard<'_, Store>, ApiError> {
    state.store.lock().map_err(|_| ApiError::Internal)
}

fn lock_users(state: &AppState) -> Result<MutexGuard<'_, UserStore>, ApiError> {
    state.users.lock().map_err(|_| ApiError::Internal)
}

// ===== Password hashing (argon2id) =====
fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| {
            eprintln!("hash error: {e}");
            ApiError::Internal
        })
}

fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

// ===== JWT =====
struct JwtConfig {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
    ttl_secs: u64,
}

impl JwtConfig {
    fn new(secret: &str, ttl_secs: u64) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["exp", "sub"]);
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            validation,
            ttl_secs,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: u64,
    exp: u64,
}

#[derive(Clone)]
struct AuthUser {
    id: u32,
}

fn issue_token(cfg: &JwtConfig, user_id: u32) -> Result<String, ApiError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::Internal)?
        .as_secs();
    let claims = Claims {
        sub: user_id.to_string(),
        iat: now,
        exp: now + cfg.ttl_secs,
    };
    encode(&Header::new(Algorithm::HS256), &claims, &cfg.encoding).map_err(|e| {
        eprintln!("jwt encode error: {e}");
        ApiError::Internal
    })
}

fn authenticate(req: &ServiceRequest) -> Result<AuthUser, ApiError> {
    let jwt = req
        .app_data::<web::Data<JwtConfig>>()
        .ok_or(ApiError::Internal)?;
    let value = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    let token = value
        .strip_prefix("Bearer ") // note the trailing space
        .ok_or(ApiError::Unauthorized)?;
    let data = decode::<Claims>(token, &jwt.decoding, &jwt.validation)
        .map_err(|_| ApiError::Unauthorized)?;
    let id = data
        .claims
        .sub
        .parse::<u32>()
        .map_err(|_| ApiError::Unauthorized)?;
    Ok(AuthUser { id })
}

// Default-deny: only the paths listed here are reachable without a token
async fn jwt_auth(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if matches!(req.path(), "/auth/register" | "/auth/login") {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    match authenticate(&req) {
        Ok(user) => {
            req.extensions_mut().insert(user);
            Ok(next.call(req).await?.map_into_boxed_body())
        }
        Err(e) => Ok(req.into_response(e.error_response())),
    }
}

// ===== Handlers: auth =====
#[post("/register")]
async fn register(
    input: web::Json<Credentials>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let cred = input.into_inner();
    cred.validate()?;
    let username = cred.username.to_ascii_lowercase();
    let password = cred.password;

    // argon2 is CPU-heavy: run it off the worker thread
    let password_hash = web::block(move || hash_password(&password))
        .await
        .map_err(|_| ApiError::Internal)??;

    let mut users = lock_users(&data)?;
    if users.users.len() >= MAX_USERS {
        return Err(ApiError::LimitReached("user limit reached".into()));
    }
    if users.users.iter().any(|u| u.username == username) {
        return Err(ApiError::Conflict("username already taken".into()));
    }
    let id = users.next_id;
    users.next_id = id.checked_add(1).ok_or(ApiError::Internal)?;
    users.users.push(User {
        id,
        username: username.clone(),
        password_hash,
    });
    Ok(HttpResponse::Created().json(RegisterResponse { id, username }))
}

#[post("/login")]
async fn login(
    input: web::Json<Credentials>,
    data: web::Data<AppState>,
    jwt: web::Data<JwtConfig>,
) -> Result<HttpResponse, ApiError> {
    let cred = input.into_inner();
    let username = cred.username.to_ascii_lowercase();
    let password = cred.password;

    // release the lock before any await
    let found = {
        let users = lock_users(&data)?;
        users.users.iter().find(|u| u.username == username).cloned()
    };

    let user_id = web::block(move || match found {
        Some(user) => verify_password(&password, &user.password_hash).then_some(user.id),
        None => {
            // spend similar time when the user does not exist
            let _ = hash_password(&password);
            None
        }
    })
    .await
    .map_err(|_| ApiError::Internal)?
    .ok_or(ApiError::InvalidCredentials)?;

    let token = issue_token(&jwt, user_id)?;
    Ok(HttpResponse::Ok().json(TokenResponse {
        token,
        token_type: "Bearer",
        expires_in: jwt.ttl_secs,
    }))
}

// ===== Handlers: memos (scoped to the owner) =====
#[get("/memos")]
async fn list_memos(
    user: web::ReqData<AuthUser>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let user = user.into_inner();
    let store = lock_store(&data)?;
    let mine: Vec<&Memo> = store
        .memos
        .iter()
        .filter(|m| m.owner_id == user.id)
        .collect();
    Ok(HttpResponse::Ok().json(mine))
}

#[get("/memos/{id}")]
async fn get_memo(
    user: web::ReqData<AuthUser>,
    path: web::Path<u32>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let user = user.into_inner();
    let id = path.into_inner();
    let store = lock_store(&data)?;
    // someone else's memo is reported as 404, same as a missing one
    let memo = store
        .memos
        .iter()
        .find(|m| m.id == id && m.owner_id == user.id)
        .ok_or(ApiError::NotFound(id))?;
    Ok(HttpResponse::Ok().json(memo))
}

#[post("/memos")]
async fn create_memo(
    user: web::ReqData<AuthUser>,
    input: web::Json<MemoInput>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let user = user.into_inner();
    let input = input.into_inner();
    input.validate()?;

    let mut store = lock_store(&data)?;
    let owned = store.memos.iter().filter(|m| m.owner_id == user.id).count();
    if owned >= MAX_MEMOS_PER_USER {
        return Err(ApiError::LimitReached("memo limit reached".into()));
    }
    let id = store.next_id;
    store.next_id = id.checked_add(1).ok_or(ApiError::Internal)?;
    let memo = Memo {
        id,
        owner_id: user.id,
        title: input.title,
        body: input.body,
    };
    store.memos.push(memo.clone());
    Ok(HttpResponse::Created().json(memo))
}

#[put("/memos/{id}")]
async fn update_memo(
    user: web::ReqData<AuthUser>,
    path: web::Path<u32>,
    input: web::Json<MemoInput>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let user = user.into_inner();
    let id = path.into_inner();
    let input = input.into_inner();
    input.validate()?;

    let mut store = lock_store(&data)?;
    let memo = store
        .memos
        .iter_mut()
        .find(|m| m.id == id && m.owner_id == user.id)
        .ok_or(ApiError::NotFound(id))?;
    memo.title = input.title;
    memo.body = input.body;
    Ok(HttpResponse::Ok().json(&*memo))
}

#[delete("/memos/{id}")]
async fn delete_memo(
    user: web::ReqData<AuthUser>,
    path: web::Path<u32>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let user = user.into_inner();
    let id = path.into_inner();
    let mut store = lock_store(&data)?;
    let pos = store
        .memos
        .iter()
        .position(|m| m.id == id && m.owner_id == user.id)
        .ok_or(ApiError::NotFound(id))?;
    store.memos.remove(pos);
    Ok(HttpResponse::NoContent().finish())
}

// ===== TLS =====
fn load_tls_config() -> std::io::Result<ServerConfig> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cert_path = std::env::var("TLS_CERT").unwrap_or_else(|_| "cert.pem".into());
    let key_path = std::env::var("TLS_KEY").unwrap_or_else(|_| "key.pem".into());

    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let mut key_reader = BufReader::new(File::open(key_path)?);

    let cert_chain = certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let key = pkcs8_private_keys(&mut key_reader).next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no PKCS#8 private key found in TLS_KEY",
        )
    })??;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, PrivateKeyDer::Pkcs8(key))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    if jwt_secret.len() < 32 {
        panic!("JWT_SECRET must be at least 32 characters");
    }
    let jwt = web::Data::new(JwtConfig::new(&jwt_secret, TOKEN_TTL_SECS));

    let state = web::Data::new(AppState {
        store: Mutex::new(Store {
            memos: Vec::new(),
            next_id: 1,
        }),
        users: Mutex::new(UserStore {
            users: Vec::new(),
            next_id: 1,
        }),
    });

    let governor_conf = GovernorConfigBuilder::default()
        .seconds_per_request(1)
        .burst_size(10)
        .finish()
        .expect("invalid governor config");

    let auth_governor_conf = GovernorConfigBuilder::default()
        .seconds_per_request(6)
        .burst_size(5)
        .finish()
        .expect("invalid auth governor config");

    let hsts_enabled = std::env::var("ENABLE_HSTS").map(|v| v == "1").unwrap_or(false);

    let tls_config = load_tls_config()?;

    println!("listening on https://127.0.0.1:8443");

    HttpServer::new(move || {
        let json_config = web::JsonConfig::default()
            .limit(4096)
            .error_handler(json_error_handler);
        let path_config = web::PathConfig::default().error_handler(path_error_handler);

        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(["GET", "POST", "PUT", "DELETE"])
            .allowed_header(header::CONTENT_TYPE)
            .allowed_header(header::AUTHORIZATION)
            .max_age(3600);

        let mut secure_headers = DefaultHeaders::new()
            .add(("X-Content-Type-Options", "nosniff"))
            .add(("X-Frame-Options", "DENY"))
            .add((
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'",
            ))
            .add(("Referrer-Policy", "no-referrer"))
            .add(("Cache-Control", "no-store"));
        if hsts_enabled {
            secure_headers = secure_headers.add((
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            ));
        }

        App::new()
            .app_data(state.clone())
            .app_data(jwt.clone())
            .app_data(json_config)
            .app_data(path_config)
            .wrap(from_fn(jwt_auth)) // innermost
            .wrap(Governor::new(&governor_conf))
            .wrap(cors)
            .wrap(secure_headers) // outermost
            .service(
                web::scope("/auth")
                    .wrap(Governor::new(&auth_governor_conf))
                    .service(register)
                    .service(login),
            )
            .service(list_memos)
            .service(get_memo)
            .service(create_memo)
            .service(update_memo)
            .service(delete_memo)
    })
    .bind_rustls_0_23(("127.0.0.1", 8443), tls_config)?
    .run()
    .await
}

