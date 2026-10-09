//! 找回服务绑定 API（T2.4 客户端入口）。
//!
//! 流程：计算联系方式哈希 → 打包找回套件（**全为密文**）→ 上传到找回服务 →
//! 在本地记录「已绑定」。服务端只持密文，无法解密任何数据。

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use vault_store::{contact_hash, VaultError};

use crate::recovery_client::RecoveryClient;
use crate::state::{ApiError, AppState};

/// 绑定请求。
#[derive(Deserialize)]
pub struct BindReq {
    /// 邮箱（或手机号）。
    pub contact: String,
    /// 联系方式类型：`email`（默认）或 `sms`。
    #[serde(default)]
    pub contact_type: Option<String>,
    /// 二次验证：当前主密码。
    pub master_password: String,
}

/// 绑定结果。
#[derive(Serialize)]
pub struct BindResp {
    /// 是否绑定成功。
    pub bound: bool,
    /// 打码后的联系方式（用于界面展示）。
    pub contact_masked: String,
}

/// 绑定状态。
#[derive(Serialize)]
pub struct StatusResp {
    /// 是否配置了找回服务。
    pub configured: bool,
    /// 服务地址（已配置时返回）。
    pub service_url: Option<String>,
    /// 是否已在本地记录绑定。
    pub bound: bool,
    /// 已绑定联系方式的哈希前缀（本地记录，用于核对是否同一个）。
    pub contact_hash_prefix: Option<String>,
}

/// 解除绑定请求。
#[derive(Deserialize)]
pub struct UnbindReq {
    /// 二次验证：当前主密码。
    pub master_password: String,
}

/// 把联系方式打码：`user@example.com` → `u***@example.com`。
fn mask_contact(contact: &str) -> String {
    match contact.split_once('@') {
        Some((local, domain)) => {
            let head: String = local.chars().take(1).collect();
            format!("{head}***@{domain}")
        }
        None => {
            let mut chars = contact.chars();
            match chars.next() {
                Some(first) => format!("{first}***"),
                None => "***".to_owned(),
            }
        }
    }
}

/// `GET /api/recovery/status`
pub async fn status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<StatusResp>, ApiError> {
    let configured = state.recovery_service_url.is_some();
    let service_url = state.recovery_service_url.clone();
    let token = AppState::token_from(&headers)?;
    let contact = state.with_vault(&token, |v| v.recovery_contact())?;
    Ok(Json(StatusResp {
        configured,
        service_url,
        bound: contact.is_some(),
        contact_hash_prefix: contact.map(|h| h.chars().take(12).collect()),
    }))
}

/// `POST /api/recovery/bind`（二次验证）
pub async fn bind(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BindReq>,
) -> Result<Json<BindResp>, ApiError> {
    let token = AppState::token_from(&headers)?;
    let service_url = state.recovery_service_url.clone().ok_or_else(|| {
        ApiError::BadRequest("未配置找回服务：启动时加 --recovery-service <url>".to_owned())
    })?;
    let contact = req.contact.trim().to_owned();
    if contact.is_empty() {
        return Err(ApiError::BadRequest("联系方式不能为空".to_owned()));
    }

    // 在锁内完成：哈希 + 打包套件（需二次验证，以解包 FDEK 并读取恢复包裹）
    let (hash, kit_json) = state.with_second_factor(&token, &req.master_password, |v| {
        let hash = contact_hash(&contact)?;
        let kit = v.recovery_kit()?;
        let json = serde_json::to_string(&kit).map_err(VaultError::Serde)?;
        Ok((hash, json))
    })?;

    // 上传到找回服务（本地调用，阻塞成本可忽略）
    let client = RecoveryClient::new(&service_url)
        .map_err(|e| ApiError::BadRequest(format!("找回服务地址无效: {e}")))?;
    let payload = serde_json::json!({
        "contact_hash": hash,
        "contact_type": req.contact_type.clone().unwrap_or_else(|| "email".to_owned()),
        "recoverywrap": kit_json,
    })
    .to_string();
    let (code, body) = client
        .post_json("/v1/recovery/bind", &payload)
        .map_err(|e| ApiError::Internal(format!("调用找回服务失败: {e}")))?;
    if !(200..300).contains(&code) {
        return Err(ApiError::Internal(format!("找回服务返回 {code}: {body}")));
    }

    // 记录本地绑定状态
    state.with_vault(&token, |v| v.set_recovery_contact(Some(&hash)))?;
    Ok(Json(BindResp {
        bound: true,
        contact_masked: mask_contact(&contact),
    }))
}

/// `POST /api/recovery/unbind`（二次验证；仅解除本地记录）
pub async fn unbind(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<UnbindReq>,
) -> Result<Json<()>, ApiError> {
    let token = AppState::token_from(&headers)?;
    state.with_second_factor(&token, &req.master_password, |v| {
        v.set_recovery_contact(None)
    })?;
    Ok(Json(()))
}

#[cfg(test)]
mod tests {
    use super::mask_contact;

    #[test]
    fn masks_email() {
        assert_eq!(mask_contact("user@example.com"), "u***@example.com");
    }

    #[test]
    fn masks_phone_like_string() {
        assert_eq!(mask_contact("13800000000"), "1***");
    }
}
