# Backend Design

## 目标

后端负责用户账户、云端剪切板、历史记录、分享关系和多设备同步通知。具体剪切板内容的读写走 HTTP API，实时通道只推送“状态已变化”的轻量消息。

## 总体架构

```text
Client
  -> HTTP API
  -> Auth / Application Services
  -> Database + Object Storage

Client
  -> Realtime Channel
  -> Notification Gateway
```

核心原则：

- HTTP API 是数据面：登录、注册、上传、查询、删除、分享。
- 实时通道是通知面：只告诉设备有更新，不传大内容。
- 小文本可直接入库，大文本、图片、二进制进入对象存储。
- 每个在线连接绑定 `user_id` 和 `device_id`，支持同一用户多设备在线。

## 模块划分

```text
api/
  auth
  users
  clipboard
  shares
  realtime

application/
  auth_service
  clipboard_service
  share_service
  device_service

domain/
  user
  device
  clipboard_item
  share

infrastructure/
  database
  object_storage
  jwt
  password_hash
  thumbnail
```

职责边界：

- `api`：路由、参数校验、响应转换。
- `application`：业务编排、事务边界、权限判断。
- `domain`：核心模型和值对象。
- `infrastructure`：数据库、对象存储、JWT、密码哈希、缩略图。

## 鉴权

使用 JWT：

- `access_token`：短有效期，用于 API 鉴权。
- `refresh_token`：长有效期，服务端只存 hash，可撤销。

请求头：

```http
Authorization: Bearer <access_token>
```

JWT payload 至少包含：

```json
{
  "sub": "user_id",
  "device_id": "device_id",
  "exp": 1770000000,
  "iat": 1770000000,
  "jti": "token_id"
}
```

## 核心数据模型

### users

```text
id
username
display_name
password_hash
created_at
updated_at
deleted_at
```

### devices

```text
id
user_id
device_name
platform
last_seen_at
created_at
```

### local_objects

```text
hash
byte_size
mime_type
storage_path
created_at
last_accessed_at
```

### clipboard_items

```text
id
owner_id
content_type
mime_type
filename
summary
text_content
object_hash
thumbnail_hash
content_hash
source_device_id
created_at
deleted_at
```

### clipboard_file_entries

```text
id
item_id
object_hash
display_name
relative_path
mime_type
byte_size
position
created_at
```

### current_clipboards

```text
user_id
clipboard_item_id
updated_at
```

### shares

```text
id
item_id
from_user_id
to_user_id
status
message
created_at
responded_at
```

## 内容存储策略

- 小文本：直接存 `clipboard_items.text_content`。
- 大文本：写入本地对象存储，DB 只存 `object_hash`。
- 图片：原图写本地对象存储，同时生成缩略图，DB 存 `object_hash` 和 `thumbnail_hash`。
- 单文件/二进制：写本地对象存储，DB 存摘要和对象 hash。
- 文件列表：`clipboard_items` 存列表摘要，`clipboard_file_entries` 存列表项；实际文件内容仍引用 `local_objects`。

本地对象使用 SHA-256 hash 作为对象 ID，路径风格类似 Git：

```text
objects/ab/cd/ef...
```

PostgreSQL 的 `local_objects.storage_path` 是由 hash 生成的路径，文件根目录由
`LOCAL_OBJECT_STORE_DIR` 配置。

## HTTP API

认证：

```text
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
GET  /api/v1/me
```

剪切板：

```text
GET    /api/v1/clipboard/current
POST   /api/v1/clipboard/current
POST   /api/v1/clipboard/current/upload
GET    /api/v1/clipboard/history?limit=20&cursor=...
DELETE /api/v1/clipboard/history/{item_id}
GET    /api/v1/clipboard/items/{item_id}
GET    /api/v1/clipboard/items/{item_id}/content
GET    /api/v1/clipboard/items/{item_id}/thumbnail
```

分享：

```text
GET  /api/v1/users/search?q=alice
POST /api/v1/shares
GET  /api/v1/shares/incoming
GET  /api/v1/shares/outgoing
POST /api/v1/shares/{share_id}/accept
POST /api/v1/shares/{share_id}/reject
```

## 实时通知

当前设计建议先使用 SSE 作为通知通道，因为服务端只推送轻量事件，具体数据仍由客户端走 API 拉取。后续如果需要 ACK、失败回报、设备能力协商或复杂同步协议，可以升级为 WebSocket。

连接模型：

```text
user_id -> device_id -> connection
```

事件示例：

```json
{
  "type": "clipboard_updated",
  "payload": {
    "item_id": "cb_123",
    "source_device_id": "dev_a",
    "updated_at": "2026-04-23T12:00:00Z"
  }
}
```

客户端收到事件后调用：

```text
GET /api/v1/clipboard/current
GET /api/v1/clipboard/history
```

## 多设备同步

同步流程：

1. 设备 A 本地剪切板变化。
2. 设备 A 上传到 `POST /clipboard/current`，请求中带 `device_id`。
3. 服务端保存记录并更新 `current_clipboards`。
4. 服务端向同用户其他在线设备推送 `clipboard_updated`。
5. 设备 B/C 收到通知后通过 API 拉取最新内容。
6. 设备 B/C 写入本地剪切板，并在本地做短期回环抑制。

防回环策略：

- 每条更新记录 `source_device_id`。
- 客户端忽略自己设备产生的事件。
- 客户端写入远端内容到本地剪切板时，设置短期 suppress 标记。
- suppress 窗口内的本地剪切板变化不再上传。

## 分享策略

分享不直接转移所有权。

流程：

1. 用户 A 创建 share，指定 `item_id` 和目标用户。
2. 用户 B 收到 `share_received` 通知。
3. 用户 B 接受后，服务端复制一条 `clipboard_item` 到 B 的历史。
4. 默认不覆盖 B 的当前云端剪切板，除非客户端明确请求。

## 错误格式

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "username or password is incorrect",
    "details": null
  }
}
```

常用状态码：

```text
200 OK
201 Created
204 No Content
400 Bad Request
401 Unauthorized
403 Forbidden
404 Not Found
409 Conflict
422 Unprocessable Entity
```

## 实现顺序

第一阶段：

- 注册、登录、刷新 token。
- 获取当前云端剪切板。
- 上传当前剪切板。
- 获取历史记录。
- 删除历史记录。

第二阶段：

- 图片/二进制对象存储。
- 缩略图生成。
- 多设备通知通道。
- 分享给指定用户。

第三阶段：

- 分页优化。
- 设备管理。
- 分享通知。
- 同步 ACK 和失败回报。
