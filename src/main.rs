use axum::{
    extract::{FromRequestParts, Json, Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::sse::{Event, KeepAlive, Sse},
    response::IntoResponse,
    response::Response,
    routing::{delete, get, post},
    Router,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use dashmap::DashMap;
use dotenvy::dotenv;
use futures::stream::{Stream, StreamExt};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres, Row};
use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::CorsLayer;

type UserId = i64;
const ACCESS_TTL: usize = 15 * 60;
const REFRESH_TTL: usize = 7 * 24 * 60 * 60;
const ADMIN_SECRET: &str = "HYsBS6V8R6O7ROlRdn+VWGt36IzUkRdl79elSpgWUSc=";

fn jwt_secret() -> Vec<u8> {
    std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set in .env file")
        .into_bytes()
}

fn now_secs() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock is before UNIX_EPOCH")
        .as_secs() as usize
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, StatusCode> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    auth.strip_prefix("Bearer ").ok_or(StatusCode::UNAUTHORIZED)
}

fn decode_token(token: &str) -> Result<Claims, StatusCode> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(&jwt_secret()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| StatusCode::UNAUTHORIZED)
}

fn encode_token(claims: &Claims) -> Result<String, StatusCode> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(&jwt_secret()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Claims {
    sub: UserId,
    exp: usize,
    token_type: String,
    is_admin: bool,
}

struct AuthUser {
    user_id: UserId,
    is_admin: bool,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers)?;
        let claims = decode_token(token)?;
        if claims.token_type != "access" {
            return Err(StatusCode::UNAUTHORIZED);
        }
        Ok(AuthUser {
            user_id: claims.sub,
            is_admin: claims.is_admin,
        })
    }
}

#[derive(Clone, Serialize, Debug)]
#[serde(tag = "type", content = "payload")]
enum AppEvent {
    DataUpdated(String),
    SharedWithYou { from_user: UserId, msg: String },
}

struct AppState {
    db: Pool<Postgres>,
    channels: DashMap<UserId, broadcast::Sender<AppEvent>>,
}

impl AppState {
    fn get_tx(&self, user_id: UserId) -> broadcast::Sender<AppEvent> {
        if let Some(entry) = self.channels.get(&user_id) {
            return entry.value().clone();
        }
        let (tx, _rx) = broadcast::channel(100);
        self.channels.insert(user_id, tx.clone());
        tx
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run database migrations");

    println!("✅ Connected to Database");

    let app_state = Arc::new(AppState {
        db: pool,
        channels: DashMap::new(),
    });

    let cors = CorsLayer::permissive();

    let admin_routes = Router::new()
        .route("/users", get(admin_list_users))
        .route("/users/:id", delete(admin_delete_user))
        .route_layer(middleware::from_fn(admin_guard));

    let app = Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/get_token", post(get_token))
        .route("/events", get(sse_handler))
        .route("/upload", post(upload_handler))
        .route("/share", post(share_handler))
        .route("/data", get(get_own_data_handler))
        .route("/data/:owner_id", get(get_shared_data_handler))
        .nest("/admin", admin_routes)
        .layer(cors)
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Server listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn admin_guard(req: Request, next: Next) -> Result<Response, StatusCode> {
    let token = bearer_token(req.headers())?;
    let claims = decode_token(token)?;
    if claims.is_admin {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

#[derive(Deserialize)]
struct RegisterReq {
    username: String,
    password: String,
    admin_secret: Option<String>,
}

async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterReq>,
) -> Result<Json<String>, (StatusCode, String)> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
        .bind(&payload.username)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if exists {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username already exists".to_string(),
        ));
    }

    let hash = hash(payload.password, DEFAULT_COST).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Hashing failed".to_string(),
        )
    })?;

    let is_admin = payload.admin_secret.as_deref() == Some(ADMIN_SECRET);
    sqlx::query("INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, $3)")
        .bind(&payload.username)
        .bind(hash)
        .bind(is_admin)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json("User registered successfully".to_string()))
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}
#[derive(Serialize)]
struct LoginResp {
    access_token: String,
    refresh_token: String,
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginReq>,
) -> Result<Json<LoginResp>, StatusCode> {
    let user_row = sqlx::query("SELECT id, password_hash, is_admin FROM users WHERE username = $1")
        .bind(&payload.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user_row = match user_row {
        Some(row) => row,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let user_id: i64 = user_row.get("id");
    let password_hash: String = user_row.get("password_hash");
    let is_admin: bool = user_row.get("is_admin");

    let valid = verify(payload.password, &password_hash).unwrap_or(false);
    if !valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let now = now_secs();

    let access_claims = Claims {
        sub: user_id,
        exp: now + ACCESS_TTL,
        token_type: "access".to_string(),
        is_admin,
    };
    let refresh_claims = Claims {
        sub: user_id,
        exp: now + REFRESH_TTL,
        token_type: "refresh".to_string(),
        is_admin,
    };

    let access_token = encode_token(&access_claims)?;
    let refresh_token = encode_token(&refresh_claims)?;

    println!("User {} ({}) logged in", payload.username, user_id);

    Ok(Json(LoginResp {
        access_token,
        refresh_token,
    }))
}

async fn sse_handler(
    AuthUser { user_id, .. }: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Sse<impl Stream<Item = Result<Event, axum::Error>>>, StatusCode> {
    let tx = state.get_tx(user_id);
    let rx = tx.subscribe();

    let stream = BroadcastStream::new(rx).map(|result| match result {
        Ok(app_event) => {
            let data = serde_json::to_string(&app_event).unwrap_or_default();
            Ok(Event::default().data(data))
        }
        Err(_) => Ok(Event::default().event("error").data("Message lag")),
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default().interval(Duration::from_secs(30))))
}

#[derive(Deserialize)]
struct UploadReq {
    content: String,
}

async fn upload_handler(
    AuthUser { user_id, .. }: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UploadReq>,
) -> impl IntoResponse {
    let exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM user_data WHERE user_id = $1)")
            .bind(user_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(false);

    if exists {
        let _ =
            sqlx::query("UPDATE user_data SET content = $1, updated_at = NOW() WHERE user_id = $2")
                .bind(&payload.content)
                .bind(user_id)
                .execute(&state.db)
                .await;
    } else {
        let _ = sqlx::query("INSERT INTO user_data (user_id, content) VALUES ($1, $2)")
            .bind(user_id)
            .bind(&payload.content)
            .execute(&state.db)
            .await;
    }

    let tx = state.get_tx(user_id);
    let _ = tx.send(AppEvent::DataUpdated("data_updated".into()));

    (StatusCode::OK, Json("Upload success"))
}

#[derive(Deserialize)]
struct ShareReq {
    target_user_id: UserId,
    message: String,
}

async fn share_handler(
    AuthUser {
        user_id: from_user_id,
        ..
    }: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ShareReq>,
) -> Result<Json<&'static str>, StatusCode> {
    let _ = sqlx::query(
        "INSERT INTO shares (from_user_id, target_user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(from_user_id)
    .bind(payload.target_user_id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let tx = state.get_tx(payload.target_user_id);
    let event = AppEvent::SharedWithYou {
        from_user: from_user_id,
        msg: payload.message,
    };
    let _ = tx.send(event);

    Ok(Json("Shared successfully"))
}

#[derive(Serialize)]
struct DataResp {
    content: String,
}

async fn get_own_data_handler(
    AuthUser { user_id, .. }: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<DataResp>, StatusCode> {
    let content: String = sqlx::query_scalar("SELECT content FROM user_data WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or_default();

    Ok(Json(DataResp { content }))
}

async fn get_shared_data_handler(
    AuthUser {
        user_id: current_user,
        ..
    }: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(owner_id): Path<UserId>,
) -> Result<Json<DataResp>, StatusCode> {
    let has_access: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM shares WHERE from_user_id = $1 AND target_user_id = $2)",
    )
    .bind(owner_id)
    .bind(current_user)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !has_access {
        return Err(StatusCode::FORBIDDEN);
    }

    let content: String = sqlx::query_scalar("SELECT content FROM user_data WHERE user_id = $1")
        .bind(owner_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or_default();

    Ok(Json(DataResp { content }))
}

#[derive(Deserialize)]
struct RefreshTokenReq {
    refresh_token: String,
}
#[derive(Serialize)]
struct RefreshTokenResp {
    access_token: String,
}

async fn get_token(
    Json(payload): Json<RefreshTokenReq>,
) -> Result<Json<RefreshTokenResp>, StatusCode> {
    let claims = decode_token(&payload.refresh_token)?;
    if claims.token_type != "refresh" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let new_claims = Claims {
        sub: claims.sub,
        exp: now_secs() + ACCESS_TTL,
        token_type: "access".to_string(),
        is_admin: claims.is_admin,
    };

    let new_token = encode_token(&new_claims)?;
    Ok(Json(RefreshTokenResp {
        access_token: new_token,
    }))
}

#[derive(Serialize, sqlx::FromRow)]
struct UserInfo {
    id: i64,
    username: String,
    is_admin: bool,
    created_at: Option<chrono::NaiveDateTime>,
}

async fn admin_list_users(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<UserInfo>>, StatusCode> {
    let users = sqlx::query_as::<_, UserInfo>(
        "SELECT id, username, is_admin, created_at FROM users ORDER BY id DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        println!("DB Error: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(users))
}

async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    Path(target_id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    let _ = sqlx::query("DELETE FROM shares WHERE from_user_id = $1 OR target_user_id = $1")
        .bind(target_id)
        .execute(&state.db)
        .await;

    let _ = sqlx::query("DELETE FROM user_data WHERE user_id = $1")
        .bind(target_id)
        .execute(&state.db)
        .await;

    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(target_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::NO_CONTENT)
}
