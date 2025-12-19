use axum::{
    extract::{State, Json, Path, FromRequestParts},
    http::{StatusCode, HeaderMap, header},
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use futures::stream::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::{sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};
use std::alloc::System;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::CorsLayer;
use axum::response::IntoResponse;
use tokio::io::Join;
// --- 1. 数据结构定义 ---

// 模拟的用户 ID 类型
type UserId = u64;

const JWT_SECRET: &[u8] = b"change-me";

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: UserId,
    exp: usize,
    token_type: String,
}

struct AuthUser(UserId);

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
            &DecodingKey::from_secret(JWT_SECRET),
            &Validation::default(),
        )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let claims = data.claims;

        if claims.token_type != "access" {
            return Err(StatusCode::UNAUTHORIZED);
        }

        Ok(AuthUser(claims.sub))
    }
}

// 消息体结构：统一推送到前端的数据格式
#[derive(Clone, Serialize, Debug)]
#[serde(tag = "type", content = "payload")]
enum AppEvent {
    // 数据更新 (Resource ID)
    DataUpdated(String),
    // 收到分享 (From User ID, Message)
    SharedWithYou { from_user: UserId, msg: String },
}

// 全局应用状态
struct AppState {
    // 核心：用户 ID -> 广播发送端
    // 使用 broadcast::Sender 可以实现“一个用户多个设备同时收到通知”
    channels: DashMap<UserId, broadcast::Sender<AppEvent>>,
    user_data: DashMap<UserId, String>,
    shares: DashMap<(UserId, UserId), ()>,
}

impl AppState {
    // 获取或创建用户的广播通道
    fn get_tx(&self, user_id: UserId) -> broadcast::Sender<AppEvent> {
        // 如果用户已在 map 中，直接返回其发送端
        if let Some(entry) = self.channels.get(&user_id) {
            return entry.value().clone();
        }

        // 如果用户不在 (第一次连接)，创建一个新通道
        // capacity 100 表示如果客户端太卡，积压超过100条消息会丢弃旧消息 (Backpressure)
        let (tx, _rx) = broadcast::channel(100);
        self.channels.insert(user_id, tx.clone());
        tx
    }
}

// --- 2. 主函数与路由 ---

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt::init();

    // 初始化共享状态
    let app_state = Arc::new(AppState {
        channels: DashMap::new(),
        user_data: DashMap::new(),
        shares: DashMap::new(),
    });

    // 配置 CORS (允许前端跨域调用)
    let cors = CorsLayer::permissive();

    let app = Router::new()
        // 1. SSE 监听接口
        .route("/login", post(login_handler))
        .route("/events", get(sse_handler))
        .route("/get_token", post(get_token))
        // 2. 业务操作接口 (POST)
        .route("/upload", post(upload_handler))
        .route("/share", post(share_handler))
        .route("/data", get(get_own_data_handler))
        .route("/data/:owner_id", get(get_shared_data_handler))
        .layer(cors)
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Server listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

// --- 3. SSE 处理器 (核心) ---

// 模拟认证：从 Header 中获取 x-user-id
async fn sse_handler(
    AuthUser(user_id): AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Sse<impl Stream<Item = Result<Event, axum::Error>>>, StatusCode> {
    // 1. 获取当前用户 ID (真实项目中应从 JWT/Session 获取)
    println!("用户 {} 已连接 SSE 通道", user_id);

    // 2. 获取该用户的广播接收端
    let tx = state.get_tx(user_id);
    let rx = tx.subscribe(); // 订阅消息

    // 3. 将广播接收端转换为 SSE 流
    // BroadcastStream 会把接收到的 AppEvent 包装成 Result
    let stream = BroadcastStream::new(rx).map(|result| {
        match result {
            Ok(app_event) => {
                // 将结构体序列化为 JSON 字符串发送
                let data = serde_json::to_string(&app_event).unwrap_or_default();
                Ok(Event::default().data(data))
            }
            Err(_lag_error) => {
                // 处理消息积压/滞后的情况
                Ok(Event::default().event("error").data("Message lag"))
            }
        }
    });

    // 4. 返回 SSE 响应，设置心跳保持连接 (KeepAlive)
    Ok(Sse::new(stream).keep_alive(KeepAlive::default().interval(Duration::from_secs(30))))
}

// --- 4. 业务处理器 (POST) ---

#[derive(Deserialize)]
struct LoginReq {
    user_id: UserId,
}

#[derive(Serialize)]
struct LoginResp {
    access_token: String,
    refresh_token: String,
}

#[derive(Serialize)]
struct DataResp {
    content: String,
}

async fn login_handler(
    Json(payload): Json<LoginReq>,
) -> impl axum::response::IntoResponse {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as usize;
    let access_exp = now + 15 * 60;
    let refresh_exp = now + 7 * 24 * 60 * 60;

    let access_claims = Claims {
        sub: payload.user_id,
        exp: access_exp,
        token_type: "access".to_string(),
    };

    let refresh_claims = Claims {
        sub: payload.user_id,
        exp: refresh_exp,
        token_type: "refresh".to_string(),
    };

    let access_token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .unwrap();

    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .unwrap();

    let resp = LoginResp {
        access_token,
        refresh_token,
    };
    println!("{} login", payload.user_id);

    (StatusCode::OK, Json(resp))
}

#[derive(Deserialize)]
struct UploadReq {
    content: String,
}

// 场景 A: 用户上传数据 -> 广播给自己 (多端同步)
async fn upload_handler(
    AuthUser(user_id): AuthUser,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UploadReq>,
) -> impl axum::response::IntoResponse {
    // 模拟获取当前用户
    println!("用户 {} 上传了数据: {}", user_id, payload.content);

    // 1. TODO: 保存数据到数据库...
    state.user_data.insert(user_id, payload.content.clone());

    // 2. 发送通知给自己 (的所有设备)
    let tx = state.get_tx(user_id);
    // 即使没有设备在线，send 也会返回接收者数量，不会报错
    let _ = tx.send(AppEvent::DataUpdated("resource_new_id_123".into()));

    println!("{} upload {}",user_id, payload.content);

    (StatusCode::OK, Json("Upload success"))
}

#[derive(Deserialize)]
struct ShareReq {
    target_user_id: UserId,
    message: String,
}

// 场景 B: 用户分享数据 -> 广播给别人
async fn share_handler(
    AuthUser(from_user_id): AuthUser,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ShareReq>,
) -> impl axum::response::IntoResponse {
    println!("用户 {} 分享给 用户 {}", from_user_id, payload.target_user_id);

    // 1. TODO: 在数据库记录权限...
    state.shares.insert((from_user_id, payload.target_user_id), ());

    // 2. 查找目标用户的通道
    // 注意：如果目标用户完全不在线（Map里没key），这里会创建一个新通道，
    // 消息发进去后因为没有接收者会直接丢弃。
    // 在真实系统中，你应该结合数据库的通知表：
    //   - 先存数据库通知表 (未读消息)
    //   - 再尝试推 SSE
    let tx = state.get_tx(payload.target_user_id);

    let event = AppEvent::SharedWithYou {
        from_user: from_user_id,
        msg: payload.message,
    };

    // 发送推送
    let receiver_count = tx.send(event).unwrap_or(0);
    println!("推送给了目标用户的 {} 个设备", receiver_count);

    (StatusCode::OK, Json("Shared successfully"))
}

async fn get_own_data_handler(
    AuthUser(user_id): AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<DataResp>, StatusCode> {
    let content = state
        .user_data
        .get(&user_id)
        .map(|entry| entry.value().clone())
        .unwrap_or_default();

    Ok(Json(DataResp { content }))
}

async fn get_shared_data_handler(
    AuthUser(current_user): AuthUser,
    State(state): State<Arc<AppState>>,
    Path(owner_id): Path<UserId>,
) -> Result<Json<DataResp>, StatusCode> {
    if state.shares.get(&(owner_id, current_user)).is_none() {
        return Err(StatusCode::FORBIDDEN);
    }

    if let Some(entry) = state.user_data.get(&owner_id) {
        let content = entry.value().clone();
        Ok(Json(DataResp { content }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
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
    Json(playLoad): Json<RefreshTokenReq>
) -> Result<Json<RefreshTokenResp>, StatusCode> {

    let token = playLoad.refresh_token;

    // --- 2. 解码 Refresh Token ---
    // decode 会自动验证：签名是否正确、是否过期(exp)
    let token_data = decode::<Claims>(
        &*token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default(),
    )
        .map_err(|_| StatusCode::UNAUTHORIZED)?; // 如果解码失败(包括过期)，返回 401

    let claims = token_data.claims;

    // --- 3. 业务验证 ---
    // 必须确保这是个 refresh token，不能用 access token 来换 access token
    if claims.token_type != "refresh" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // --- 4. 生成新的 Access Token ---
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as usize;

    let expires_in = 15 * 60; // 15分钟有效期
    let access_exp = now + expires_in;

    let new_access_claims = Claims {
        sub: claims.sub, // 延续用户的 ID
        exp: access_exp,
        token_type: "access".to_string(),
    };

    let new_access_token = encode(
        &Header::default(),
        &new_access_claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?; // 编码失败属于服务器错误

    // --- 5. 返回结果 ---
    // 使用 Result::Ok 包裹 Json，解决了之前的类型不匹配问题
    Ok(Json(RefreshTokenResp {
        access_token: new_access_token,
    }))
}