//! 账号卡片读取：详情、列表、检索、高敏感字段揭示（含审计）。

use rusqlite::{params, OptionalExtension};

use security_core::seal;

use crate::error::VaultError;
use crate::models::{AccountDetail, AccountSummary, FieldType, Importance, SecretFieldView};
use crate::Vault;

fn decrypt_string(key: &[u8; 32], sealed: &[u8]) -> Result<String, VaultError> {
    let bytes = seal::open(key, sealed)?;
    String::from_utf8(bytes).map_err(|_| VaultError::Crypto(security_core::SecurityError::Decryption))
}

impl Vault {
    /// 读取账号详情（含备注与高敏感字段脱敏列表）。
    pub fn get_account(&self, id: &str) -> Result<AccountDetail, VaultError> {
        let key = self.key();
        let row = self
            .conn
            .query_row(
                "SELECT app_name_enc, url_enc, username_enc, notes_enc, importance, updated_at
                 FROM accounts WHERE id = ?1",
                params![id],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Option<Vec<u8>>>(1)?,
                        r.get::<_, Option<Vec<u8>>>(2)?,
                        r.get::<_, Option<Vec<u8>>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| VaultError::AccountNotFound(id.to_owned()))?;
        let app_name = decrypt_string(key, &row.0)?;
        let url = seal::open_opt(key, row.1.as_deref())?;
        let username = seal::open_opt(key, row.2.as_deref())?;
        let notes = seal::open_opt(key, row.3.as_deref())?;
        let secrets = self.secret_views(id)?;
        self.record_audit("view_account", None, Some(id))?;
        Ok(AccountDetail {
            summary: AccountSummary {
                id: id.to_owned(),
                app_name,
                url,
                username,
                importance: Importance::parse(&row.4),
                field_types: secrets.iter().map(|s| s.field_type).collect(),
                updated_at: row.5,
            },
            notes,
            secrets,
        })
    }

    /// 列出全部账号摘要（解密 app 名/网址/账号，不含密码）。
    pub fn list_accounts(&self) -> Result<Vec<AccountSummary>, VaultError> {
        self.all_summaries()
    }

    /// 关键词检索（对 app 名 / 网址 / 账号做不区分大小写的子串匹配）。
    pub fn search_accounts(&self, query: &str) -> Result<Vec<AccountSummary>, VaultError> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return self.all_summaries();
        }
        let matched = self
            .all_summaries()?
            .into_iter()
            .filter(|s| {
                s.app_name.to_lowercase().contains(&needle)
                    || s.url
                        .as_deref()
                        .is_some_and(|u| u.to_lowercase().contains(&needle))
                    || s.username
                        .as_deref()
                        .is_some_and(|u| u.to_lowercase().contains(&needle))
            })
            .collect();
        Ok(matched)
    }

    /// 揭示高敏感字段明文（调用方须已完成二次验证），并写入审计。
    pub fn reveal_secret(
        &self,
        account_id: &str,
        field_type: FieldType,
    ) -> Result<String, VaultError> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT sealed FROM secret_fields WHERE account_id = ?1 AND field_type = ?2",
                params![account_id, field_type.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        let sealed =
            sealed.ok_or_else(|| VaultError::SecretNotFound(field_type.as_str().to_owned()))?;
        let value = decrypt_string(self.key(), &sealed)?;
        self.record_audit("reveal_secret", Some(field_type.category()), Some(account_id))?;
        Ok(value)
    }

    fn secret_views(&self, account_id: &str) -> Result<Vec<SecretFieldView>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT field_type, masked_preview, requires_second_factor
             FROM secret_fields WHERE account_id = ?1 ORDER BY field_type",
        )?;
        let rows = stmt.query_map(params![account_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (field_type, masked, requires) = row?;
            if let Some(ft) = FieldType::parse(&field_type) {
                out.push(SecretFieldView {
                    field_type: ft,
                    masked_preview: masked,
                    requires_second_factor: requires != 0,
                });
            }
        }
        Ok(out)
    }

    fn secret_types(&self, account_id: &str) -> Result<Vec<FieldType>, VaultError> {
        Ok(self
            .secret_views(account_id)?
            .into_iter()
            .map(|s| s.field_type)
            .collect())
    }

    fn all_summaries(&self) -> Result<Vec<AccountSummary>, VaultError> {
        let key = self.key();
        let mut stmt = self.conn.prepare(
            "SELECT id, app_name_enc, url_enc, username_enc, importance, updated_at
             FROM accounts ORDER BY updated_at DESC, id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, app_enc, url_enc, user_enc, importance, updated_at) = row?;
            out.push(AccountSummary {
                app_name: decrypt_string(key, &app_enc)?,
                url: seal::open_opt(key, url_enc.as_deref())?,
                username: seal::open_opt(key, user_enc.as_deref())?,
                importance: Importance::parse(&importance),
                field_types: self.secret_types(&id)?,
                updated_at,
                id,
            });
        }
        Ok(out)
    }
}
