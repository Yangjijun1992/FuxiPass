//! 邮箱找回闭环：**忘记主密码 → 邮箱验证码 → 用恢复密钥重置**。
//!
//! 三个接口都在**未解锁**状态下可用（用户此时正被锁在门外）：
//!
//! 1. `/api/recover/request-code` —— 输入邮箱，向找回服务申请验证码；
//! 2. `/api/recover/verify-code` —— 校验验证码，取回**加密套件**并换一次性令牌；
//! 3. `/api/recover/reset` —— 用「一次性令牌 + 恢复密钥 + 新主密码」完成重置。
//!
//! **安全性质**：验证码只是第二因素；真正能解开数据的是**恢复密钥**（256-bit）。
//! 即便有人拿到验证码，没有恢复密钥也无法解包。服务端全程只持有密文。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use vault_store::{contact_hash, recover_with_kit, RecoveryKit};

use crate::recovery_client::RecoveryClient;
use crate::state::{ApiError, AppState, PendingRecovery};

/// 一次性找回令牌的有效期。
const RECOVERY_TOKEN_TTL_MS: u64 = 5 * 60 * 1000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// 申请验证码请求。
#[derive(Deserialize)]
pub struct RequestCodeReq {
    /// 绑定时使用的邮箱（或手机号）。
    pub contact: String,
}

/// 申请验证码响应。
#[derive(Serialize)]
pub struct RequestCodeResp {
    /// 一次性请求 ID。
    pub request_id: String,
    /// 验证码有效期（秒）。
    pub ttl_sec: u64,
    /// 本地联调时回显的验证码（生产环境经邮件/短信下发时为 `null`）。
    pub dev_code: Option<String>,
}

/// 校验验证码请求。
#[derive(Deserialize)]
pub struct VerifyCodeReq {
    /// 申请时返回的请求 ID。
    pub request_id: String,
    /// 收到的验证码。
    pub code: String,
}

/// 校验验证码响应。
#[derive(Serialize)]
pub struct VerifyCodeResp {
    /// 一次性令牌，用于下一步重置。
    pub recovery_token: String,
}

/// 重置请求。
#[derive(Deserialize)]
pub struct ResetReq {
    /// 上一步得到的一次性令牌。
    pub recovery_token: String,
    /// 恢复密钥（导入/初始化时打印的那串）。
    pub recovery_key: String,
    /// 新主密码。
    pub new_master_password: String,
}

/// 重置响应。
#[derive(Serialize)]
pub struct ResetResp {
    /// 是否成功。
    pub ok: bool,
}

fn service_url(state: &AppState) -> Result<String, ApiError> {
    state.recovery_service_url.clone().ok_or_else(|| {
        ApiError::BadRequest("未配置找回服务：启动时加 --recovery-service <url>".to_owned())
    })
}

fn client_for(url: &str) -> Result<RecoveryClient, ApiError> {
    RecoveryClient::new(url).map_err(|e| ApiError::BadRequest(format!("找回服务地址无效: {e}")))
}

/// 从服务响应中解析 JSON；非 2xx 时把服务端错误转成可读信息。
fn parse_service_json(code: u16, body: &str) -> Result<serde_json::Value, ApiError> {
    if !(200..300).contains(&code) {
        let message = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v["error"]["message"].as_str().map(str::to_owned))
            .unwrap_or_else(|| body.to_owned());
        return Err(ApiError::BadRequest(format!("找回服务：{message}")));
    }
    serde_json::from_str(body).map_err(|_| ApiError::Internal("找回服务返回了非法 JSON".to_owned()))
}

/// `POST /api/recover/request-code`（无需解锁）
pub async fn request_code(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RequestCodeReq>,
) -> Result<Json<RequestCodeResp>, ApiError> {
    let url = service_url(&state)?;
    let hash = contact_hash(&req.contact).map_err(ApiError::from_vault)?;
    let client = client_for(&url)?;

    let payload = serde_json::json!({ "contact_hash": hash }).to_string();
    let (code, body) = client
        .post_json("/v1/recovery/challenge", &payload)
        .map_err(|e| ApiError::Internal(format!("调用找回服务失败: {e}")))?;
    let json = parse_service_json(code, &body)?;

    Ok(Json(RequestCodeResp {
        request_id: json["request_id"].as_str().unwrap_or_default().to_owned(),
        ttl_sec: json["ttl_sec"].as_u64().unwrap_or(300),
        dev_code: json["dev_code"].as_str().map(str::to_owned),
    }))
}

/// `POST /api/recover/verify-code`（无需解锁；成功后取回加密套件）
pub async fn verify_code(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyCodeReq>,
) -> Result<Json<VerifyCodeResp>, ApiError> {
    let url = service_url(&state)?;
    let client = client_for(&url)?;

    let payload = serde_json::json!({
        "request_id": req.request_id,
        "code": req.code,
    })
    .to_string();
    let (code, body) = client
        .post_json("/v1/recovery/verify", &payload)
        .map_err(|e| ApiError::Internal(format!("调用找回服务失败: {e}")))?;
    let json = parse_service_json(code, &body)?;

    // 服务端只返回密文套件；真正解包需要恢复密钥（下一步）
    let kit_json = json["recoverywrap"]
        .as_str()
        .ok_or_else(|| ApiError::Internal("找回服务未返回套件".to_owned()))?
        .to_owned();

    // 生成一次性令牌并暂存套件
    let token = {
        use security_core::cipher::CryptoRng;
        CryptoRng::bytes(32)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let mut slot = state
        .recovery
        .lock()
        .map_err(|_| ApiError::Internal("recovery lock poisoned".to_owned()))?;
    *slot = Some(PendingRecovery {
        token: token.clone(),
        kit_json,
        expires_at_ms: now_ms().saturating_add(RECOVERY_TOKEN_TTL_MS),
    });

    Ok(Json(VerifyCodeResp {
        recovery_token: token,
    }))
}

/// `POST /api/recover/reset`（无需解锁；需要恢复密钥）
pub async fn reset(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ResetReq>,
) -> Result<Json<ResetResp>, ApiError> {
    if req.new_master_password.is_empty() {
        return Err(ApiError::BadRequest("新主密码不能为空".to_owned()));
    }
    // 取出并校验一次性令牌
    let kit_json = {
        let mut slot = state
            .recovery
            .lock()
            .map_err(|_| ApiError::Internal("recovery lock poisoned".to_owned()))?;
        let Some(pending) = slot.as_ref() else {
            return Err(ApiError::BadRequest(
                "找回会话不存在或已失效，请重新获取验证码".to_owned(),
            ));
        };
        if pending.token != req.recovery_token {
            return Err(ApiError::BadRequest("找回令牌不正确".to_owned()));
        }
        if now_ms() > pending.expires_at_ms {
            *slot = None;
            return Err(ApiError::BadRequest(
                "找回会话已过期，请重新获取验证码".to_owned(),
            ));
        }
        pending.kit_json.clone()
    };

    let kit: RecoveryKit = serde_json::from_str(&kit_json)
        .map_err(|_| ApiError::Internal("套件格式不正确".to_owned()))?;

    // 真正重置（恢复密钥在此校验；错误会被拒绝）
    recover_with_kit(
        &state.db_path,
        &kit,
        &req.recovery_key,
        &req.new_master_password,
    )
    .map_err(|e| match e {
        vault_store::VaultError::RecoveryFailed => {
            ApiError::BadRequest("恢复密钥不正确，或套件已损坏".to_owned())
        }
        other => ApiError::from_vault(other),
    })?;

    // 一次性：用掉即失效；同时清掉可能存在的解锁会话
    if let Ok(mut slot) = state.recovery.lock() {
        *slot = None;
    }
    if let Ok(mut session) = state.session.lock() {
        *session = None;
    }
    Ok(Json(ResetResp { ok: true }))
}
