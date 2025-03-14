use super::{
    super::Prov,
    models::{CreateUser, User},
    service::UserService,
};
use actix_web::{
    delete, get, post, put,
    web::{self, scope, Json, Path},
    Either, HttpResponse, Responder, Result, Scope,
};
use rand::Rng;

pub fn create_scope() -> Scope {
    scope("/api/users")
        .service(get_user)
        .service(create_user)
        .service(update_user)
        .service(delete_user)
}
pub fn cpu_scope() -> Scope {
    scope("/api").service(cpu_intensive_task)
}

#[get("/{user_id}")]
async fn get_user(provider: Prov, user_id: Path<i64>) -> Result<impl Responder> {
    let service = provider.provide::<UserService>();
    let result = service.get(*user_id).await;
    match result {
        Ok(user) => Ok(Either::Left(web::Json(user))),
        Err(error) => Ok(Either::Right((
            web::Json(error),
            actix_web::http::StatusCode::BAD_REQUEST,
        ))),
    }
}

#[post("/")]
async fn create_user(provider: Prov, user: Json<CreateUser>) -> Result<impl Responder> {
    let service = provider.provide::<UserService>();
    let result = service.create(&user).await;
    match result {
        Ok(user) => Ok(Either::Left(web::Json(user))),
        Err(error) => Ok(Either::Right((
            web::Json(error),
            actix_web::http::StatusCode::BAD_REQUEST,
        ))),
    }
}

#[put("/")]
async fn update_user(provider: Prov, user: Json<User>) -> Result<impl Responder> {
    let service = provider.provide::<UserService>();
    let result = service.update(&user).await;
    match result {
        Ok(_) => Ok(Either::Left(HttpResponse::Ok())),
        Err(error) => Ok(Either::Right((
            web::Json(error),
            actix_web::http::StatusCode::BAD_REQUEST,
        ))),
    }
}

#[delete("/{user_id}")]
async fn delete_user(provider: Prov, user_id: Path<i64>) -> Result<impl Responder> {
    let service = provider.provide::<UserService>();
    let result = service.delete(*user_id).await;
    match result {
        Ok(_) => Ok(Either::Left(HttpResponse::Ok())),
        Err(error) => Ok(Either::Right((
            web::Json(error),
            actix_web::http::StatusCode::BAD_REQUEST,
        ))),
    }
}


// cpu
async fn process_cpu() -> String {
    let mut s = String::new();
    let mut rng = rand::thread_rng();
    for _ in 0..300000 {
        s.push((rng.gen_range(0..26) + 97) as u8 as char);
    }
    let s = s.as_bytes();
    let mut matches = 0;
    for i in 0..s.len() {
        for j in i + 1..s.len() {
            if s[i] == s[j] {
                matches += 1;
            }
        }
    }
    return format!("Found {} matches", matches);
}

#[get("/cpu")]
async fn cpu_intensive_task() -> String {
    let start = std::time::Instant::now();
    let result = process_cpu().await;
    // tracing::debug!("Found {} matches", matches);
    // tracing::debug!("Elapsed time: {:?}", start.elapsed());
    return format!("Elapsed time: {:?} found: {}", start.elapsed(), result);
}
