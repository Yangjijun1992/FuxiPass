//! 账号卡片写入：新建、更新、删除（含高敏感字段的字段级加密落库）。

use rusqlite::params;

use security_core::seal;

use crate::error::VaultError;
use crate::models::{masked_preview, AccountInput, FieldType};
use crate::util::{new_id, now_millis};
use crate::Vault;

/// 从输入中提取待写入的高敏感字段。
fn secret_pairs(input: &AccountInput) -> Vec<(FieldType, &str)> {
    let mut pairs = Vec::new();
    if let Some(v) = input.login_password.as_deref().filter(|s| !s.is_empty()) {
        pairs.push((FieldType::LoginPassword, v));
    }
    if let Some(v) = input.secondary_password.as_deref().filter(|s| !s.is_empty()) {
        pairs.push((FieldType::SecondaryPassword, v));
    }
    if let Some(v) = input.payment_password.as_deref().filter(|s| !s.is_empty()) {
        pairs.push((FieldType::PaymentPassword, v));
    }
    if let Some(v) = input.api_key.as_deref().filter(|s| !s.is_empty()) {
        pairs.push((FieldType::ApiKey, v));
    }
    pairs
}

impl Vault {
    /// 新建账号卡片，返回新卡片 ID。
    pub fn create_account(&self, input: &AccountInput) -> Result<String, VaultError> {
        input.validate()?;
        let id = new_id();
        let ts = now_millis();
        let key = self.key();
        self.conn.execute(
            "INSERT INTO accounts
             (id, app_name_enc, url_enc, username_enc, notes_enc, importance, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                seal::seal(key, input.app_name.as_bytes())?,
                seal::seal_opt(key, input.url.as_deref())?,
                seal::seal_opt(key, input.username.as_deref())?,
                seal::seal_opt(key, input.notes.as_deref())?,
                input.importance.as_str(),
                ts,
                ts
            ],
        )?;
        self.replace_secrets(&id, input, &ts)?;
        self.record_audit("create_account", None, Some(&id))?;
        Ok(id)
    }

    /// 更新账号卡片（高敏感字段整体替换）。
    pub fn update_account(&self, id: &str, input: &AccountInput) -> Result<(), VaultError> {
        input.validate()?;
        let ts = now_millis();
        let key = self.key();
        let affected = self.conn.execute(
            "UPDATE accounts
             SET app_name_enc = ?2, url_enc = ?3, username_enc = ?4, notes_enc = ?5,
                 importance = ?6, updated_at = ?7
             WHERE id = ?1",
            params![
                id,
                seal::seal(key, input.app_name.as_bytes())?,
                seal::seal_opt(key, input.url.as_deref())?,
                seal::seal_opt(key, input.username.as_deref())?,
                seal::seal_opt(key, input.notes.as_deref())?,
                input.importance.as_str(),
                ts
            ],
        )?;
        if affected == 0 {
            return Err(VaultError::AccountNotFound(id.to_owned()));
        }
        self.replace_secrets(id, input, &ts)?;
        self.record_audit("update_account", None, Some(id))?;
        Ok(())
    }

    /// 删除账号卡片（级联删除其高敏感字段）。
    pub fn delete_account(&self, id: &str) -> Result<(), VaultError> {
        let affected = self
            .conn
            .execute("DELETE FROM accounts WHERE id = ?1", params![id])?;
        if affected == 0 {
            return Err(VaultError::AccountNotFound(id.to_owned()));
        }
        self.record_audit("delete_account", None, Some(id))?;
        Ok(())
    }

    fn replace_secrets(
        &self,
        account_id: &str,
        input: &AccountInput,
        ts: &str,
    ) -> Result<(), VaultError> {
        self.conn.execute(
            "DELETE FROM secret_fields WHERE account_id = ?1",
            params![account_id],
        )?;
        let key = self.key();
        for (field_type, value) in secret_pairs(input) {
            let requires_2fa = if field_type.requires_second_factor() {
                1_i64
            } else {
                0_i64
            };
            self.conn.execute(
                "INSERT INTO secret_fields
                 (id, account_id, field_type, sealed, masked_preview, requires_second_factor, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    new_id(),
                    account_id,
                    field_type.as_str(),
                    seal::seal(key, value.as_bytes())?,
                    masked_preview(value),
                    requires_2fa,
                    ts
                ],
            )?;
        }
        Ok(())
    }
}
