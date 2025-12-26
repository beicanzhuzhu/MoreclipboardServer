use axum::{
    extract::{State, Json, Path, FromRequestParts, Request},
    http::{StatusCode, HeaderMap, header},
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post, delete},
    Router,
    middleware::{self, Next},
    response::Response,
};
use dashmap::DashMap;
use futures::stream::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::{sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::CorsLayer;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres, Row};
use bcrypt::{hash, verify, DEFAULT_COST};
use dotenvy::dotenv;
use std::env;
use axum::response::IntoResponse;
// --- 1. 数据结构定义 ---

// Postgres 的 BIGINT 对应 Rust 的 i64
type UserId = i64;

// 动态获取 Secret
fn get_jwt_secret() -> Vec<u8> {
    std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set in .env file")
        .into_bytes()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Claims {
    sub: UserId,
    exp: usize,
    token_type: String,
    is_admin: bool, // 将管理员权限放入 Token 中
}

// 提取器：普通用户
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
        let headers = &parts.headers;

        let value = headers
            .get(header::AUTHORIZATION)
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let auth_str = value
            .to_str()
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        if !auth_str.starts_with("Bearer ") {
            return Err(StatusCode::UNAUTHORIZED);
        }

        let token = &auth_str["Bearer ".len()..];

        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(&get_jwt_secret()),
            &Validation::default(),
        )
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let claims = data.claims;

        if claims.token_type != "access" {
            return Err(StatusCode::UNAUTHORIZED);
        }

        Ok(AuthUser {
            user_id: claims.sub,
            is_admin: claims.is_admin
        })
    }
}

// SSE 消息体
#[derive(Clone, Serialize, Debug)]
#[serde(tag = "type", content = "payload")]
enum AppEvent {
    DataUpdated(String),
    SharedWithYou { from_user: UserId, msg: String },
}

// 全局应用状态
struct AppState {
    // 数据库连接池 (用于持久化数据)
    db: Pool<Postgres>,
    // SSE 通道 (仅用于内存中的实时通讯)
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

// --- 2. 主函数与路由 ---

#[tokio::main]
async fn main() {
    dotenv().ok(); // 加载 .env
    tracing_subscriber::fmt::init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // 连接数据库
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    println!("✅ Connected to Database at koqio.tech");

    let app_state = Arc::new(AppState {
        db: pool,
        channels: DashMap::new(),
    });

    let cors = CorsLayer::permissive();

    // 后台管理路由 (需要管理员权限)
    let admin_routes = Router::new()
        .route("/users", get(admin_list_users))
        .route("/users/:id", delete(admin_delete_user))
        .route_layer(middleware::from_fn(admin_guard));

    let app = Router::new()
        // 公开接口
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/get_token", post(get_token))
        // 用户业务接口 (SSE & Data)
        .route("/events", get(sse_handler))
        .route("/upload", post(upload_handler))
        .route("/share", post(share_handler))
        .route("/data", get(get_own_data_handler))
        .route("/data/:owner_id", get(get_shared_data_handler))
        // 挂载后台管理接口
        .nest("/admin", admin_routes)
        .layer(cors)
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Server listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

// --- 3. 中间件：管理员守卫 ---
async fn admin_guard(
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // 这里我们需要手动解析 AuthUser，因为中间件运行在 Handler 之前
    let parts = req.headers();
    let auth_header = parts.get(header::AUTHORIZATION)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = &auth_header["Bearer ".len()..];
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&get_jwt_secret()),
        &Validation::default(),
    ).map_err(|_| StatusCode::UNAUTHORIZED)?;

    if token_data.claims.is_admin {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::FORBIDDEN) // 403 禁止访问
    }
}

// --- 4. 处理器实现 ---

// 注册请求结构
#[derive(Deserialize)]
struct RegisterReq {
    username: String,
    password: String,
    // 注册暗号，如果匹配则设为管理员 (仅用于演示，实际生产需谨慎)
    admin_secret: Option<String>,
}

// 注册接口
async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterReq>,
) -> Result<Json<String>, (StatusCode, String)> {
    // 1. 检查用户名是否存在
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
        .bind(&payload.username)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if exists {
        return Err((StatusCode::BAD_REQUEST, "Username already exists".to_string()));
    }

    // 2. 密码加密
    let hash = hash(payload.password, DEFAULT_COST)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Hashing failed".to_string()))?;

    // 3. 判断是否为管理员
    let is_admin = payload.admin_secret.as_deref() == Some("HYsBS6V8R6O7ROlRdn+VWGt36IzUkRdl79elSpgWUSc=");

    // 4. 插入数据库
    sqlx::query("INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, $3)")
        .bind(&payload.username)
        .bind(hash)
        .bind(is_admin)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json("User registered successfully".to_string()))
}

// 登录请求
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

// 登录接口 (数据库验证)
async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginReq>,
) -> Result<Json<LoginResp>, StatusCode> {
    // 1. 查询用户
    let user_row = sqlx::query("SELECT id, password_hash, is_admin FROM users WHERE username = $1")
        .bind(&payload.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user_row = match user_row {
        Some(row) => row,
        None => return Err(StatusCode::UNAUTHORIZED), // 用户不存在
    };

    let user_id: i64 = user_row.get("id");
    let password_hash: String = user_row.get("password_hash");
    let is_admin: bool = user_row.get("is_admin");

    // 2. 验证密码
    let valid = verify(payload.password, &password_hash).unwrap_or(false);
    if !valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // 3. 生成 Token
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let access_exp = now + 15 * 60;
    let refresh_exp = now + 7 * 24 * 60 * 60;

    let access_claims = Claims {
        sub: user_id,
        exp: access_exp,
        token_type: "access".to_string(),
        is_admin,
    };
    let refresh_claims = Claims {
        sub: user_id,
        exp: refresh_exp,
        token_type: "refresh".to_string(),
        is_admin,
    };

    let secret = get_jwt_secret();
    let access_token = encode(&Header::default(), &access_claims, &EncodingKey::from_secret(&secret)).unwrap();
    let refresh_token = encode(&Header::default(), &refresh_claims, &EncodingKey::from_secret(&secret)).unwrap();

    println!("User {} ({}) logged in", payload.username, user_id);

    Ok(Json(LoginResp {
        access_token,
        refresh_token,
    }))
}

// SSE Handler
async fn sse_handler(
    AuthUser { user_id, .. }: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Sse<impl Stream<Item = Result<Event, axum::Error>>>, StatusCode> {
    let tx = state.get_tx(user_id);
    let rx = tx.subscribe();

    let stream = BroadcastStream::new(rx).map(|result| {
        match result {
            Ok(app_event) => {
                let data = serde_json::to_string(&app_event).unwrap_or_default();
                Ok(Event::default().data(data))
            }
            Err(_) => Ok(Event::default().event("error").data("Message lag")),
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default().interval(Duration::from_secs(30))))
}

#[derive(Deserialize)]
struct UploadReq {
    content: String,
}

// 上传/更新数据 (写入 DB + 推送)
async fn upload_handler(
    AuthUser { user_id, .. }: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UploadReq>,
) -> impl IntoResponse {
    // 1. 写入数据库 (Upsert: 如果存在则更新，不存在则插入)
    // 这里为了简化，假设每个用户只有一条数据。如果想存多条，去掉 ON CONFLICT 逻辑即可。
    // 我们先查询是否已存在
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_data WHERE user_id = $1)")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(false);

    if exists {
        let _ = sqlx::query("UPDATE user_data SET content = $1, updated_at = NOW() WHERE user_id = $2")
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

    // 2. 广播给自己
    let tx = state.get_tx(user_id);
    let _ = tx.send(AppEvent::DataUpdated("data_updated".into()));

    (StatusCode::OK, Json("Upload success"))
}

#[derive(Deserialize)]
struct ShareReq {
    target_user_id: UserId,
    message: String,
}

// 分享逻辑
async fn share_handler(
    AuthUser { user_id: from_user_id, .. }: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ShareReq>,
) -> Result<Json<&'static str>, StatusCode> {
    // 1. 记录分享权限到数据库
    let _ = sqlx::query("INSERT INTO shares (from_user_id, target_user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(from_user_id)
        .bind(payload.target_user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // 2. 推送通知
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

// 获取自己的数据
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

// 获取他人分享的数据
async fn get_shared_data_handler(
    AuthUser { user_id: current_user, .. }: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(owner_id): Path<UserId>,
) -> Result<Json<DataResp>, StatusCode> {
    // 1. 检查是否有分享记录
    let has_access: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM shares WHERE from_user_id = $1 AND target_user_id = $2)")
        .bind(owner_id)
        .bind(current_user)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !has_access {
        return Err(StatusCode::FORBIDDEN);
    }

    // 2. 获取数据
    let content: String = sqlx::query_scalar("SELECT content FROM user_data WHERE user_id = $1")
        .bind(owner_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or_default();

    Ok(Json(DataResp { content }))
}

// Token 刷新
#[derive(Deserialize)]
struct RefreshTokenReq {
    refresh_token: String,
}
#[derive(Serialize)]
struct RefreshTokenResp {
    access_token: String,
}

async fn get_token(
    Json(payload): Json<RefreshTokenReq>
) -> Result<Json<RefreshTokenResp>, StatusCode> {
    let token = payload.refresh_token;
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(&get_jwt_secret()),
        &Validation::default(),
    ).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let claims = token_data.claims;
    if claims.token_type != "refresh" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let new_claims = Claims {
        sub: claims.sub,
        exp: now + 15 * 60,
        token_type: "access".to_string(),
        is_admin: claims.is_admin,
    };

    let new_token = encode(&Header::default(), &new_claims, &EncodingKey::from_secret(&get_jwt_secret()))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(RefreshTokenResp { access_token: new_token }))
}

// --- 5. 后台管理接口实现 ---

#[derive(Serialize)]
struct UserInfo {
    id: i64,
    username: String,
    is_admin: bool,
    created_at: Option<chrono::NaiveDateTime>,
}

// Admin: 获取所有用户
async fn admin_list_users(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<UserInfo>>, StatusCode> {
    // 需要 sqlx feature "chrono" 来处理时间
    let users = sqlx::query_as!(
        UserInfo,
        "SELECT id, username, is_admin as \"is_admin!\", created_at FROM users ORDER BY id DESC"
    )
        .fetch_all(&state.db)
        .await
        .map_err(|e| {
            println!("DB Error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(users))
}

// Admin: 删除用户
async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    Path(target_id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    // 删除相关数据 (需注意外键约束，这里简单演示)
    // 实际生产建议用 ON DELETE CASCADE 或软删除
    let _ = sqlx::query("DELETE FROM shares WHERE from_user_id = $1 OR target_user_id = $1")
        .bind(target_id)
        .execute(&state.db).await;

    let _ = sqlx::query("DELETE FROM user_data WHERE user_id = $1")
        .bind(target_id)
        .execute(&state.db).await;

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