//! 审计日志：记录高敏感操作（不落任何明文），供合规查询（PRD §7）。

use rusqlite::params;

use crate::error::VaultError;
use crate::models::AuditEntry;
use crate::util::now_millis;
use crate::Vault;

impl Vault {
    /// 写入一条审计记录（仅操作类型与字段类别，绝不含明文）。
    pub(crate) fn record_audit(
        &self,
        operation: &str,
        field_category: Option<&str>,
        account_id: Option<&str>,
    ) -> Result<(), VaultError> {
        self.conn.execute(
            "INSERT INTO audit_logs (ts, operation, field_category, account_id)
             VALUES (?1, ?2, ?3, ?4)",
            params![now_millis(), operation, field_category, account_id],
        )?;
        Ok(())
    }

    /// 读取最近的审计记录（按时间倒序）。
    pub fn list_audit(&self, limit: i64) -> Result<Vec<AuditEntry>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, operation, field_category, account_id
             FROM audit_logs ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
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
