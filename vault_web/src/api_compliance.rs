//! 隐私与合规 API（T4.3 审计查询/导出、T4.4 PIPL 数据权利）。

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};
use vault_store::{AuditEntry, DataSummary};

use crate::state::{ApiError, AppState};

/// 删除全部数据时必须逐字输入的确认短语。
pub const PURGE_CONFIRM_PHRASE: &str = "删除全部数据";

/// 删除全部数据请求。
#[derive(Deserialize)]
pub struct PurgeReq {
    /// 二次验证：当前主密码。
    pub master_password: String,
    /// 确认短语，必须逐字等于 `删除全部数据`。
    pub confirm: String,
}

/// 删除结果。
#[derive(Serialize)]
pub struct PurgeResp {
    /// 已删除的账号数。
    pub purged_accounts: usize,
}

/// 审计查询参数。
#[derive(Deserialize)]
pub struct AuditQuery {
    /// 返回条数上限（默认 100，上限 1000）。
    #[serde(default)]
    pub limit: Option<i64>,
    /// 按操作类型过滤。
    #[serde(default)]
    pub operation: Option<String>,
}

/// `GET /api/compliance/summary`
pub async fn summary(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<DataSummary>, ApiError> {
    let token = AppState::token_from(&headers)?;
    let summary = state.with_vault(&token, |v| v.data_summary())?;
    Ok(Json(summary))
}

/// `POST /api/vault/purge`（二次验证 + 确认短语；不可逆）
pub async fn purge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PurgeReq>,
) -> Result<Json<PurgeResp>, ApiError> {
    if req.confirm != PURGE_CONFIRM_PHRASE {
        return Err(ApiError::BadRequest(format!(
            "确认短语不正确，请输入「{PURGE_CONFIRM_PHRASE}」"
        )));
    }
    let token = AppState::token_from(&headers)?;
    let purged_accounts =
        state.with_second_factor(&token, &req.master_password, |v| v.purge_all_accounts())?;
    Ok(Json(PurgeResp { purged_accounts }))
}

/// `GET /api/audit?limit=&operation=`
pub async fn audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    let token = AppState::token_from(&headers)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let operation = query.operation.as_deref().filter(|s| !s.is_empty());
    let entries = state.with_vault(&token, |v| v.list_audit_filtered(limit, operation))?;
    Ok(Json(entries))
}

/// `GET /api/audit/export`（CSV 下载）
pub async fn audit_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = AppState::token_from(&headers)?;
    let entries = state.with_vault(&token, |v| v.list_audit_filtered(1000, None))?;
    let mut csv = String::from("timestamp,operation,field_category,account_id\n");
    for entry in entries {
        csv.push_str(&csv_escape(&entry.ts));
        csv.push(',');
        csv.push_str(&csv_escape(&entry.operation));
        csv.push(',');
        csv.push_str(&csv_escape(entry.field_category.as_deref().unwrap_or("")));
        csv.push(',');
        csv.push_str(&csv_escape(entry.account_id.as_deref().unwrap_or("")));
        csv.push('\n');
    }
    let mut response = Response::new(Body::from(csv));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"fuxipass-audit.csv\""),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}
