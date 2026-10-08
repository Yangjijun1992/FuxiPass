//! 加密备份导出 / 导入（T3.6，PRD §2.3 换机迁移、§3.5.4 安全导出）。
//!
//! 备份文件 = 口令派生的 KEK 加密整份 JSON 载荷，复用 `security_core::wrap` 的
//! 信封格式（含 KDF 参数与 AES-256-GCM 密文），因此：
//! - 备份文件本身**不含任何明文**；
//! - 口令错误或文件被篡改时解密必然失败；
//! - 换机迁移只需「备份文件 + 口令」，无需云同步。
//!
//! 说明：当前账号模型有 登录/二级/支付/密钥 四个密码槽位；
//! BackupAccount 与之一一对应，故导出→导入可无损往返。

use rusqlite::params;
use serde::{Deserialize, Serialize};

use security_core::{seal, KdfParams, Wrap};

use crate::accounts_read::decrypt_string;
use crate::error::VaultError;
use crate::models::{AccountInput, FieldType, Importance};
use crate::util::now_millis;
use crate::Vault;

/// 备份载荷的格式标识。
pub const BACKUP_FORMAT: &str = "fuxipass-backup";
/// 备份口令最小长度。
pub const MIN_BACKUP_PASSPHRASE_LEN: usize = 8;

/// 单个账号的备份表示（含全部明文密码，整体再被加密）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupAccount {
    /// 应用/网站名。
    pub app_name: String,
    /// 网址。
    pub url: Option<String>,
    /// 账号/用户名。
    pub username: Option<String>,
    /// 备注。
    pub notes: Option<String>,
    /// 重要度。
    pub importance: Importance,
    /// 登录密码。
    pub login_password: Option<String>,
    /// 二级密码。
    pub secondary_password: Option<String>,
    /// 支付密码。
    pub payment_password: Option<String>,
    /// API Key / 密钥。
    pub api_key: Option<String>,
}

/// 备份载荷（加密前的明文结构）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPayload {
    /// 格式标识。
    pub format: String,
    /// 导出时间（epoch 毫秒）。
    pub exported_at: String,
    /// 全部账号。
    pub accounts: Vec<BackupAccount>,
}

impl Vault {
    /// 导出加密备份，返回备份文件字节（JSON 信封）。
    ///
    /// 需要 `--passphrase`（≥8 位）；该口令**可以不同于主密码**，
    /// 使备份可交由第三方保管而不暴露主密码。
    pub fn export_backup(&self, passphrase: &str) -> Result<Vec<u8>, VaultError> {
        if passphrase.len() < MIN_BACKUP_PASSPHRASE_LEN {
            return Err(VaultError::InvalidInput(format!(
                "备份口令至少 {MIN_BACKUP_PASSPHRASE_LEN} 位"
            )));
        }
        let payload = BackupPayload {
            format: BACKUP_FORMAT.to_owned(),
            exported_at: now_millis(),
            accounts: self.collect_backup_accounts()?,
        };
        let plaintext = serde_json::to_vec(&payload)?;
        let kdf = KdfParams::with_random_salt();
        let kek = kdf.derive_kek(passphrase.as_bytes())?;
        let envelope = security_core::wrap::wrap_with_key(kek.as_array(), Some(kdf), &plaintext)?;
        self.record_audit("export_backup", None, None)?;
        Ok(serde_json::to_vec_pretty(&envelope)?)
    }

    /// 导入加密备份（合并写入当前库；逐条写入，单条失败不阻断）。
    pub fn import_backup(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<crate::ImportOutcome, VaultError> {
        let payload = read_backup(data, passphrase)?;
        let inputs: Vec<AccountInput> = payload.accounts.into_iter().map(to_input).collect();
        let outcome = self.import_inputs(&inputs);
        self.record_audit("import_backup", None, None)?;
        Ok(outcome)
    }

    fn collect_backup_accounts(&self) -> Result<Vec<BackupAccount>, VaultError> {
        let key = self.key();
        let mut stmt = self.conn.prepare(
            "SELECT id, app_name_enc, url_enc, username_enc, notes_enc, importance
             FROM accounts ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        let mut accounts = Vec::new();
        for row in rows {
            let (id, app_enc, url_enc, user_enc, notes_enc, importance) = row?;
            let mut account = BackupAccount {
                app_name: decrypt_string(key, &app_enc)?,
                url: seal::open_opt(key, url_enc.as_deref())?,
                username: seal::open_opt(key, user_enc.as_deref())?,
                notes: seal::open_opt(key, notes_enc.as_deref())?,
                importance: Importance::parse(&importance),
                login_password: None,
                secondary_password: None,
                payment_password: None,
                api_key: None,
            };
            for (field_type, value) in self.secret_values(&id)? {
                match field_type {
                    FieldType::LoginPassword => account.login_password = Some(value),
                    FieldType::SecondaryPassword => account.secondary_password = Some(value),
                    FieldType::PaymentPassword => account.payment_password = Some(value),
                    FieldType::ApiKey | FieldType::PrivateKey | FieldType::Totp => {
                        account.api_key = Some(value);
                    }
                }
            }
            accounts.push(account);
        }
        Ok(accounts)
    }

    fn secret_values(&self, account_id: &str) -> Result<Vec<(FieldType, String)>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT field_type, sealed FROM secret_fields WHERE account_id = ?1")?;
        let rows = stmt.query_map(params![account_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let key = self.key();
        let mut out = Vec::new();
        for row in rows {
            let (field_type, sealed) = row?;
            if let Some(ft) = FieldType::parse(&field_type) {
                out.push((ft, decrypt_string(key, &sealed)?));
            }
        }
        Ok(out)
    }
}

fn to_input(account: BackupAccount) -> AccountInput {
    AccountInput {
        app_name: account.app_name,
        url: account.url,
        username: account.username,
        notes: account.notes,
        importance: account.importance,
        login_password: account.login_password,
        secondary_password: account.secondary_password,
        payment_password: account.payment_password,
        api_key: account.api_key,
    }
}

/// 用口令解密备份文件并解析出载荷（不写入任何库）。
pub fn read_backup(data: &[u8], passphrase: &str) -> Result<BackupPayload, VaultError> {
    let envelope: Wrap = serde_json::from_slice(data)
        .map_err(|_| VaultError::InvalidInput("备份文件格式不正确".to_owned()))?;
    let kdf = envelope
        .kdf
        .clone()
        .ok_or_else(|| VaultError::InvalidInput("备份文件缺少 KDF 参数".to_owned()))?;
    let kek = kdf.derive_kek(passphrase.as_bytes())?;
    let plaintext = security_core::wrap::unwrap_with_key(kek.as_array(), &envelope)
        .map_err(|_| VaultError::InvalidInput("备份口令错误或文件已损坏".to_owned()))?;
    let payload: BackupPayload = serde_json::from_slice(&plaintext)
        .map_err(|_| VaultError::InvalidInput("备份内容解析失败".to_owned()))?;
    if payload.format != BACKUP_FORMAT {
        return Err(VaultError::InvalidInput("备份格式标识不匹配".to_owned()));
    }
    Ok(payload)
}
