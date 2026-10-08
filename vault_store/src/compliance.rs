//! 数据主体权利（PIPL 合规，T4.4）。
//!
//! 提供「查看 / 导出 / 删除」三类数据权利的后端能力：
//! - 查看：账号数、审计条数等概览；
//! - 导出：由 `backup::export_backup` 提供（加密备份）；
//! - 删除：`purge_all_accounts` 清空全部账号（保留库结构与主密码，可继续使用）。
//!
//! 注意：删除是**不可逆**的破坏性操作，调用方必须先做二次验证与显式确认，
//! 并由用户自行决定是否先导出备份。

use rusqlite::params;

use crate::error::VaultError;
use crate::models::AuditEntry;
use crate::Vault;

/// 数据概览（合规页展示用）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DataSummary {
    /// 账号卡片数。
    pub accounts: usize,
    /// 密码字段数。
    pub secret_fields: usize,
    /// 审计记录数。
    pub audit_entries: usize,
}

impl Vault {
    /// 数据概览。
    pub fn data_summary(&self) -> Result<DataSummary, VaultError> {
        let accounts: i64 = self
            .conn
            .query_row("SELECT count(*) FROM accounts", [], |r| r.get(0))?;
        let secret_fields: i64 =
            self.conn
                .query_row("SELECT count(*) FROM secret_fields", [], |r| r.get(0))?;
        let audit_entries: i64 =
            self.conn
                .query_row("SELECT count(*) FROM audit_logs", [], |r| r.get(0))?;
        Ok(DataSummary {
            accounts: usize::try_from(accounts).unwrap_or(usize::MAX),
            secret_fields: usize::try_from(secret_fields).unwrap_or(usize::MAX),
            audit_entries: usize::try_from(audit_entries).unwrap_or(usize::MAX),
        })
    }

    /// 删除全部账号数据（`secret_fields` 由外键级联清除），返回删除的账号数。
    ///
    /// 库结构、主密码、恢复密钥与审计日志**保持不变**，删除后库仍可正常使用。
    pub fn purge_all_accounts(&self) -> Result<usize, VaultError> {
        let removed = self.conn.execute("DELETE FROM accounts", [])?;
        self.record_audit("purge_all_accounts", None, None)?;
        Ok(removed)
    }

    /// 清空全部审计日志（用户行使「删除权」时可选）。
    pub fn purge_audit_logs(&self) -> Result<usize, VaultError> {
        let removed = self.conn.execute("DELETE FROM audit_logs", [])?;
        self.record_audit("purge_audit_logs", None, None)?;
        Ok(removed)
    }

    /// 按操作类型过滤审计记录（`operation` 为 `None` 时返回全部）。
    pub fn list_audit_filtered(
        &self,
        limit: i64,
        operation: Option<&str>,
    ) -> Result<Vec<AuditEntry>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, operation, field_category, account_id
             FROM audit_logs
             WHERE (?1 IS NULL OR operation = ?1)
             ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![operation, limit], |r| {
            Ok(AuditEntry {
                ts: r.get(0)?,
                operation: r.get(1)?,
                field_category: r.get(2)?,
                account_id: r.get(3)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}
