//! 保险库生命周期：初始化、解锁、恢复、修改主密码、密码提示词。
//!
//! 对应 PRD §2.1（密钥体系）与 §2.2（恢复/重置）。

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use security_core::{Dek, KdfParams, RecoveryKey, Wrap};

use crate::error::VaultError;
use crate::schema::{self, SCHEMA_VERSION};
use crate::util::now_millis;

/// 已解锁的保险库：持有 SQLite 连接与 DEK。
pub struct Vault {
    pub(crate) conn: Connection,
    pub(crate) dek: Dek,
}

impl Vault {
    /// 字段级加密使用的 256-bit 密钥引用。
    pub(crate) fn key(&self) -> &[u8; 32] {
        self.dek.as_array()
    }

    /// 修改主密码：仅重包 DEK（不重加密全量数据）。
    pub fn change_master_password(&mut self, new_password: &str) -> Result<(), VaultError> {
        if new_password.is_empty() {
            return Err(VaultError::InvalidInput(
                "new master password must not be empty".to_owned(),
            ));
        }
        let new_kdf = KdfParams::with_random_salt();
        let new_kek = new_kdf.derive_kek(new_password.as_bytes())?;
        let new_dekwrap = security_core::wrap_dek(&new_kek, &self.dek, Some(new_kdf.clone()))?;
        self.conn.execute(
            "UPDATE meta SET kdf_params = ?1, dekwrap = ?2 WHERE id = 1",
            params![
                serde_json::to_string(&new_kdf)?,
                serde_json::to_string(&new_dekwrap)?
            ],
        )?;
        self.record_audit("change_master_password", None, None)?;
        Ok(())
    }

    /// 设置密码提示词（纯本地，应避免包含密码本身）。
    pub fn set_hint(&self, hint: Option<&str>) -> Result<(), VaultError> {
        self.conn
            .execute("UPDATE meta SET hint = ?1 WHERE id = 1", params![hint])?;
        Ok(())
    }

    /// 读取密码提示词。
    pub fn hint(&self) -> Result<Option<String>, VaultError> {
        let hint: Option<String> = self
            .conn
            .query_row("SELECT hint FROM meta WHERE id = 1", [], |row| row.get(0))
            .optional()?
            .flatten();
        Ok(hint)
    }

    /// 重新生成恢复密钥（需已解锁）。返回新的显示串，**旧恢复密钥立即失效**。
    pub fn regenerate_recovery_key(&self) -> Result<String, VaultError> {
        let recovery = security_core::generate_recovery_key();
        let recoverywrap = security_core::wrap_dek_via_recovery(&recovery, &self.dek)?;
        self.conn.execute(
            "UPDATE meta SET recoverywrap = ?1 WHERE id = 1",
            params![serde_json::to_string(&recoverywrap)?],
        )?;
        self.record_audit("regenerate_recovery_key", None, None)?;
        Ok(recovery.to_display())
    }
}

/// 读取密码提示词（**无需解锁**：提示词以明文存于 meta，供解锁界面显示）。
///
/// 主密码遗忘时用户需要看到提示词，因此该读取不能依赖解锁会话。
pub fn read_hint(path: &Path) -> Result<Option<String>, VaultError> {
    if !path.exists() {
        return Err(VaultError::NotInitialized);
    }
    let conn = open_connection(path)?;
    let hint: Option<Option<String>> = conn
        .query_row("SELECT hint FROM meta WHERE id = 1", [], |row| row.get(0))
        .optional()?;
    Ok(hint.flatten())
}

/// 打开数据库连接并启用外键约束（级联删除依赖此设置，每个连接都需开启）。
fn open_connection(path: &Path) -> Result<Connection, VaultError> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    Ok(conn)
}

/// 初始化结果：新保险库的恢复密钥（需用户离线保管）。
pub struct InitResult {
    /// 人类可读、便于抄录的恢复密钥显示串。
    pub recovery_key_display: String,
}

/// 初始化一个新保险库：生成 DEK 与恢复密钥，写入包裹与 KDF 参数。
///
/// 若目标文件已存在则拒绝，避免覆盖已有数据。
pub fn initialize(path: &Path, master_password: &str) -> Result<InitResult, VaultError> {
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    if master_password.is_empty() {
        return Err(VaultError::InvalidInput(
            "master password must not be empty".to_owned(),
        ));
    }
    let conn = open_connection(path)?;
    schema::apply(&conn)?;

    let kdf = KdfParams::with_random_salt();
    let kek = kdf.derive_kek(master_password.as_bytes())?;
    let dek = security_core::generate_dek();
    let recovery = security_core::generate_recovery_key();
    let dekwrap = security_core::wrap_dek(&kek, &dek, Some(kdf.clone()))?;
    let recoverywrap = security_core::wrap_dek_via_recovery(&recovery, &dek)?;

    conn.execute(
        "INSERT INTO meta (id, schema_version, kdf_params, dekwrap, recoverywrap, hint, created_at)
         VALUES (1, ?1, ?2, ?3, ?4, NULL, ?5)",
        params![
            SCHEMA_VERSION,
            serde_json::to_string(&kdf)?,
            serde_json::to_string(&dekwrap)?,
            serde_json::to_string(&recoverywrap)?,
            now_millis()
        ],
    )?;

    Ok(InitResult {
        recovery_key_display: recovery.to_display(),
    })
}

/// 用主密码解锁保险库（主密码错误时返回 `InvalidInput`）。
pub fn unlock(path: &Path, master_password: &str) -> Result<Vault, VaultError> {
    let conn = open_connection(path)?;
    let (kdf_json, dekwrap_json) = read_kdf_and_dekwrap(&conn)?;
    let kdf: KdfParams = serde_json::from_str(&kdf_json)?;
    let dekwrap: Wrap = serde_json::from_str(&dekwrap_json)?;
    let kek = kdf.derive_kek(master_password.as_bytes())?;
    let dek = security_core::unwrap_dek(&kek, &dekwrap).map_err(|_| {
        VaultError::InvalidInput("incorrect master password".to_owned())
    })?;
    Ok(Vault { conn, dek })
}

/// 忘记主密码时，用恢复密钥重置主密码（DEK 与数据保持不变）。
pub fn recover(
    path: &Path,
    recovery_key_display: &str,
    new_master_password: &str,
) -> Result<(), VaultError> {
    if new_master_password.is_empty() {
        return Err(VaultError::InvalidInput(
            "new master password must not be empty".to_owned(),
        ));
    }
    let conn = open_connection(path)?;
    let recoverywrap_json: Option<String> = conn
        .query_row("SELECT recoverywrap FROM meta WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()?
        .ok_or(VaultError::NotInitialized)?;
    let recoverywrap_json = recoverywrap_json.ok_or(VaultError::RecoveryFailed)?;

    let recovery =
        RecoveryKey::from_display(recovery_key_display).map_err(|_| VaultError::RecoveryFailed)?;
    let recovery_wrap: Wrap = serde_json::from_str(&recoverywrap_json)?;
    let dek = security_core::unwrap_dek_via_recovery(&recovery, &recovery_wrap)
        .map_err(|_| VaultError::RecoveryFailed)?;

    let new_kdf = KdfParams::with_random_salt();
    let new_kek = new_kdf.derive_kek(new_master_password.as_bytes())?;
    let new_dekwrap = security_core::wrap_dek(&new_kek, &dek, Some(new_kdf.clone()))?;
    conn.execute(
        "UPDATE meta SET kdf_params = ?1, dekwrap = ?2 WHERE id = 1",
        params![
            serde_json::to_string(&new_kdf)?,
            serde_json::to_string(&new_dekwrap)?
        ],
    )?;
    Ok(())
}

/// 校验主密码是否正确（用于高敏感操作的二次验证），不改变保险库状态。
pub fn verify_master_password(path: &Path, master_password: &str) -> Result<bool, VaultError> {
    let conn = open_connection(path)?;
    let (kdf_json, dekwrap_json) = read_kdf_and_dekwrap(&conn)?;
    let kdf: KdfParams = serde_json::from_str(&kdf_json)?;
    let dekwrap: Wrap = serde_json::from_str(&dekwrap_json)?;
    let Ok(kek) = kdf.derive_kek(master_password.as_bytes()) else {
        return Ok(false);
    };
    Ok(security_core::unwrap_dek(&kek, &dekwrap).is_ok())
}

fn read_kdf_and_dekwrap(conn: &Connection) -> Result<(String, String), VaultError> {
    conn.query_row(
        "SELECT kdf_params, dekwrap FROM meta WHERE id = 1",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )
    .optional()?
    .ok_or(VaultError::NotInitialized)
}
