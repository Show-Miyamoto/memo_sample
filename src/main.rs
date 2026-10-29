use actix_web::{delete, get, post, put, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// Return a note as a response
#[derive(Serialize, Clone)]
struct Memo {
    id: u32,
    title: String,
    body: String,
}

//Repuest body(shared for creation and updates)
#[derive(Deserialize)]
struct MemoInput {
    title: String,
    body: String,
}

//
struct Store {
    memos: Vec<Memo>,
    next_id: u32,
}

struct AppState {
    store: Mutex<Store>,
}

#[get("/memos")]
async fn list_memos(data:web::Data<AppState>) -> impl Responder {
    let store = data.store.lock().unwrap();
    HttpResponse::Ok().json(&store.memos)
}

#[get("/memos/{id}")]
async fn get_memo(path: web::Path<u32>, data: web::Data<AppState>) -> impl Responder {
    let id = path.into_inner();
    let store = data.store.lock().unwrap();
    match store.memos.iter().find(|m| m.id == id) {
        Some(memo) => HttpResponse::Ok().json(memo),
        None => HttpResponse::NotFound().body("memo not found!!!"),
    }
}

#[post("/memos")]
async fn create_memo(
    input: web::Json<MemoInput>,
    data: web::Data<AppState>,
    ) -> impl Responder {
    let mut store = data.store.lock().unwrap();
    let input = input.into_inner();
    let memo = Memo {
        id: store.next_id,
        title: input.title,
        body: input.body,
    };
    store.next_id += 1;
    store.memos.push(memo.clone());
    HttpResponse::Created().json(memo)
}

#[put("/memos/{id}")]
async fn update_memo(
    path: web::Path<u32>,
    input: web::Json<MemoInput>,
    data: web::Data<AppState>,
) -> impl Responder {
    let id = path.into_inner();
    let mut store = data.store.lock().unwrap();
    match store.memos.iter_mut().find(|m| m.id == id) {
        Some(memo) => {
            let input = input.into_inner();
            memo.title = input.title;
            memo.body = input.body;
            HttpResponse::Ok().json(&*memo)
        }
        None => HttpResponse::NotFound().body("memo not found"),
    }
}

#[delete("/memos/{id}")]
async fn delete_memo(path: web::Path<u32>, data: web::Data<AppState>) -> impl Responder {
    let id = path.into_inner();
    let mut store = data.store.lock().unwrap();
    let before = store.memos.len();
    store.memos.retain(|m| m.id != id);
    if store.memos.len() < before {
        HttpResponse::NoContent().finish()
    } else {
        HttpResponse::NotFound().body("memo not found")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    //
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
