use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_example::CreateUser;
use axum_example::Module;
use axum_example::UserService;
use nject::{injectable, provider};
use rand::Rng;

#[provider]
#[injectable]
pub struct Provider(#[import] Module);

#[tokio::main]
async fn main() {
    #[provider]
    struct InitProvider;

    let provider: &'static Provider = Box::leak(Box::new(InitProvider.provide()));
    let app = Router::new()
        .route("/api/users", post(create_user))
        .route("/api/users/:id", get(get_user))
        .route("/api/cpu", get(cpu_intensive_task))
        .with_state(provider);

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("listening on {}", addr); // run our app with hyper, listening globally on port 3000
    axum::serve(listener, app).await.unwrap();
}

async fn create_user(
    State(prov): State<&'static Provider>,
    Json(user): Json<CreateUser>,
) -> impl IntoResponse {
    let service = prov.provide::<UserService>();
    let user = service.create(user);
    (StatusCode::CREATED, Json(user))
}

async fn get_user(
    State(prov): State<&'static Provider>,
    Path(user_id): Path<usize>,
) -> impl IntoResponse {
    let service = prov.provide::<UserService>();
    let user = service.get(user_id);
    (StatusCode::OK, Json(user))
}





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

async fn cpu_intensive_task() -> String {
    let start = std::time::Instant::now();
    let result = process_cpu().await;
    // tracing::debug!("Found {} matches", matches);
    // tracing::debug!("Elapsed time: {:?}", start.elapsed());
    return format!("Elapsed time: {:?} found: {}", start.elapsed(), result);
}