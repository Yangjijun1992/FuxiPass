//! 智能导入与加密备份的 API（T2.6/T2.7/T3.6）。
//!
//! 两者都涉及批量数据进出，单独成模块以保持 `api.rs` 聚焦于账号与鉴权。

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};
use vault_store::{ImportCandidate, ImportOutcome};

use crate::api::require_second_factor;
use crate::state::{ApiError, AppState};

/// 导入解析请求。
#[derive(Deserialize)]
pub struct ImportParseReq {
    /// 用户粘贴的原始文本。
    pub text: String,
}

/// 导入解析响应。
#[derive(Serialize)]
pub struct ImportParseResp {
    /// 解析出的候选账号。
    pub candidates: Vec<ImportCandidate>,
}

/// 导入提交请求（含二次验证主密码）。
#[derive(Deserialize)]
pub struct ImportCommitReq {
    /// 用户确认后的候选列表。
    pub candidates: Vec<ImportCandidate>,
    /// 二次验证：当前主密码。
    pub master_password: String,
}

/// 导出备份请求（二次验证）。
#[derive(Deserialize)]
pub struct BackupExportReq {
    /// 备份口令（可与主密码不同；≥8 位）。
    pub passphrase: String,
    /// 二次验证：当前主密码。
    pub master_password: String,
}

/// 导入备份请求（二次验证）。
#[derive(Deserialize)]
pub struct BackupImportReq {
    /// 备份文件内容（JSON 文本）。
    pub data: String,
    /// 备份口令。
    pub passphrase: String,
    /// 二次验证：当前主密码。
    pub master_password: String,
}

/// `POST /api/import/parse`
pub async fn import_parse(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ImportParseReq>,
) -> Result<Json<ImportParseResp>, ApiError> {
    let token = AppState::token_from(&headers)?;
    state.with_vault(&token, |_v| Ok(()))?;
    let candidates = vault_store::parse_notes(&req.text);
    Ok(Json(ImportParseResp { candidates }))
}

/// `POST /api/import/commit`（二次验证后批量入库）
pub async fn import_commit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ImportCommitReq>,
) -> Result<Json<ImportOutcome>, ApiError> {
    let token = AppState::token_from(&headers)?;
    require_second_factor(&state, &req.master_password)?;
    let outcome = state.with_vault(&token, |v| Ok(v.import_candidates(&req.candidates)))?;
    Ok(Json(outcome))
}

/// `POST /api/backup/export`（二次验证；返回可下载的加密备份文件）
pub async fn export_backup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BackupExportReq>,
) -> Result<Response, ApiError> {
    let token = AppState::token_from(&headers)?;
    require_second_factor(&state, &req.master_password)?;
    let data = state.with_vault(&token, |v| v.export_backup(&req.passphrase))?;
    let mut response = Response::new(Body::from(data));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"fuxipass-backup.json\""),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

/// `POST /api/backup/import`（二次验证；合并写入当前库）
pub async fn import_backup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BackupImportReq>,
) -> Result<Json<ImportOutcome>, ApiError> {
    let token = AppState::token_from(&headers)?;
    require_second_factor(&state, &req.master_password)?;
    let outcome = state.with_vault(&token, |v| {
        v.import_backup(req.data.as_bytes(), &req.passphrase)
    })?;
    Ok(Json(outcome))
}
