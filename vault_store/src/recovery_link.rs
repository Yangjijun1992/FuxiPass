//! 找回服务绑定（T2.4 客户端侧）。
//!
//! 与 `recovery_service`（服务端）配合实现 PRD §2.2 的「邮箱/短信找回」：
//!
//! 1. **绑定**：客户端计算联系方式哈希 + 打包「找回套件」（恢复密钥包裹），
//!    上传给服务端保存。服务端只持密文，无法解密。
//! 2. **找回**：在新机器上验证邮箱验证码 → 取回套件 → 用**恢复密钥**解包。
//!
//! 安全要点：
//! - 联系方式**不发明文**给服务端，只发 Argon2id 哈希（抗枚举）；
//! - 上传的套件全是密文（需恢复密钥才能解开）。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rusqlite::params;

use crate::error::VaultError;
use crate::Vault;

/// 找回套件格式版本。
pub const KIT_VERSION: u32 = 1;

/// 联系方式哈希的固定应用盐（非机密；用于保证同一联系方式得到同一哈希）。
const CONTACT_SALT: &[u8] = b"fuxipass.contact.v1";

/// 计算联系方式哈希（确定性 + 抗枚举）。
///
/// 使用 Argon2id（19 MiB / t=2 / p=1）与固定盐：同一联系方式总是得到同一哈希
/// （服务端据此查找），而高计算开销让「拿邮箱字典批量枚举」代价高昂。
pub fn contact_hash(contact: &str) -> Result<String, VaultError> {
    use security_core::bytes::Base64Bytes;
    use security_core::kdf::{KdfAlgorithm, KdfParams};

    let normalized = contact.trim().to_lowercase();
    if normalized.is_empty() {
        return Err(VaultError::InvalidInput("联系方式不能为空".to_owned()));
    }
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        salt: Base64Bytes(CONTACT_SALT.to_vec()),
        m_cost_kib: 19 * 1024,
        t_cost: 2,
        p_cost: 1,
    };
    let key = params.derive_kek(normalized.as_bytes())?;
    Ok(URL_SAFE_NO_PAD.encode(key.as_bytes()))
}

/// 找回套件（上传给服务端的全部内容，均为密文）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryKit {
    /// 格式版本。
    pub version: u32,
    /// DEK 的**恢复密钥包裹**（`meta.recoverywrap`）——这是找回时真正需要的东西。
    pub recovery_wrap: String,
    /// FDEK 的恢复密钥包裹（若该库启用了 FDEK）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fdek_wrap_recovery: Option<String>,
}

impl Vault {
    /// 打包找回套件（**只含密文**；无需二次验证，因为服务端也解不开）。
    pub fn recovery_kit(&self) -> Result<RecoveryKit, VaultError> {
        let row: (Option<String>, Option<String>) = self.conn.query_row(
            "SELECT recoverywrap, fdek_wrap_recovery FROM meta WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let recovery_wrap = row.0.ok_or(VaultError::RecoveryFailed)?;
        Ok(RecoveryKit {
            version: KIT_VERSION,
            recovery_wrap,
            fdek_wrap_recovery: row.1,
        })
    }

    /// 记录已绑定的联系方式哈希（`None` 表示解除绑定）。
    pub fn set_recovery_contact(&self, hash: Option<&str>) -> Result<(), VaultError> {
        self.conn.execute(
            "UPDATE meta SET recovery_contact_hash = ?1 WHERE id = 1",
            params![hash],
        )?;
        self.record_audit(
            if hash.is_some() {
                "bind_recovery"
            } else {
                "unbind_recovery"
            },
            None,
            None,
        )?;
        Ok(())
    }

    /// 已绑定的联系方式哈希（若有）。
    pub fn recovery_contact(&self) -> Result<Option<String>, VaultError> {
        let row: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT recovery_contact_hash FROM meta WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .ok();
        Ok(row.flatten())
    }
}

/// 用**外部找回套件**重置主密码（不依赖本地 `meta` 中的包裹）。
///
/// 用于「忘记主密码 → 邮箱验证取回套件 → 用恢复密钥重置」流程：
/// 即使本地的恢复包裹缺失或损坏，只要拿到服务端保存的套件 + 恢复密钥，
/// 就能解出 DEK 并用新主密码重新封装，**数据不受影响**。
///
/// # 错误
/// - 恢复密钥错误 / 套件损坏 → [`VaultError::RecoveryFailed`]
/// - 保险库未初始化 → [`VaultError::NotInitialized`]
pub fn recover_with_kit(
    path: &std::path::Path,
    kit: &RecoveryKit,
    recovery_key_display: &str,
    new_master_password: &str,
) -> Result<(), VaultError> {
    use crate::fdek;
    use crate::lockout;
    use crate::schema;
    use security_core::{RecoveryKey, Wrap};

    if new_master_password.is_empty() {
        return Err(VaultError::InvalidInput(
            "new master password must not be empty".to_owned(),
        ));
    }
    if kit.version != KIT_VERSION {
        return Err(VaultError::InvalidInput(format!(
            "不支持的找回套件版本: {}",
            kit.version
        )));
    }

    let conn = crate::vault::open_connection(path)?;
    if !schema::is_initialized(&conn)? {
        return Err(VaultError::NotInitialized);
    }
    let recovery =
        RecoveryKey::from_display(recovery_key_display).map_err(|_| VaultError::RecoveryFailed)?;

    // 1) 用恢复密钥从套件中解出 DEK
    let dekwrap: Wrap =
        serde_json::from_str(&kit.recovery_wrap).map_err(|_| VaultError::RecoveryFailed)?;
    let dek_raw = security_core::wrap::unwrap_with_key(recovery.as_array(), &dekwrap)
        .map_err(|_| VaultError::RecoveryFailed)?;
    let dek = security_core::Dek::from_bytes(&dek_raw).map_err(|_| VaultError::RecoveryFailed)?;

    // 2) 若套件含 FDEK 的恢复包裹，一并解出（保证高敏感字段仍可读）
    let fdek_key = match kit.fdek_wrap_recovery.as_deref() {
        Some(json) => {
            let wrap: Wrap = serde_json::from_str(json).map_err(|_| VaultError::RecoveryFailed)?;
            let raw = security_core::wrap::unwrap_with_key(recovery.as_array(), &wrap)
                .map_err(|_| VaultError::RecoveryFailed)?;
            Some(security_core::Dek::from_bytes(&raw).map_err(|_| VaultError::RecoveryFailed)?)
        }
        None => None,
    };

    // 3) 用新主密码重新封装 DEK（与 FDEK）
    let new_kdf = security_core::KdfParams::with_random_salt();
    let new_kek = new_kdf.derive_kek(new_master_password.as_bytes())?;
    let new_dekwrap = security_core::wrap_dek(&new_kek, &dek, Some(new_kdf.clone()))?;
    conn.execute(
        "UPDATE meta SET kdf_params = ?1, dekwrap = ?2 WHERE id = 1",
        rusqlite::params![
            serde_json::to_string(&new_kdf)?,
            serde_json::to_string(&new_dekwrap)?
        ],
    )?;
    if let Some(key) = fdek_key {
        // 同时刷新 FDEK 的主密码包裹与恢复包裹（沿用套件中的恢复包裹内容）
        fdek::rewrap_fdek_for_password(&conn, key.as_array(), new_master_password)?;
        if let Some(recovery_wrap_json) = kit.fdek_wrap_recovery.as_deref() {
            conn.execute(
                "UPDATE meta SET fdek_wrap_recovery = ?1 WHERE id = 1",
                rusqlite::params![recovery_wrap_json],
            )?;
        }
    }
    lockout::reset(&conn)?;
    Ok(())
}
