//! 防爆破退避锁定验收测试（T2.3）。
//!
//! 覆盖 PRD §3.4.3：
//! 连续输错 5 次锁 5 分钟、退避至上限 30 分钟、**绝不删除数据**、
//! 恢复密钥通道不受锁定限制、二次验证接口同样限速。

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use security_core::cipher::CryptoRng;
use vault_store::{
    initialize, lock_status, recover, unlock, verify_master_password, AccountInput, FieldType,
    Importance, VaultError,
};

struct TempVault {
    path: PathBuf,
}

impl TempVault {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fuxipass_lockout_{}.db",
            URL_SAFE_NO_PAD.encode(CryptoRng::bytes(12))
        ));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempVault {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut p = self.path.clone().into_os_string();
            p.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(p));
        }
    }
}

const MASTER: &str = "correct horse battery staple";

fn sample_input() -> AccountInput {
    AccountInput {
        app_name: "中国建设银行".to_owned(),
        url: Some("https://ebank.ccb.com".to_owned()),
        username: Some("zhangsan_123".to_owned()),
        notes: None,
        importance: Importance::Finance,
        login_password: Some("LoginPw!234".to_owned()),
        secondary_password: Some("888444".to_owned()),
        payment_password: None,
        api_key: None,
    }
}

fn bootstrapped() -> (TempVault, String) {
    let tv = TempVault::new();
    let init = initialize(tv.path(), MASTER).unwrap();
    (tv, init.recovery_key_display)
}


/// 断言结果为「锁定」，返回剩余秒数。避免 `unwrap_err` 要求 `Vault: Debug`。
fn expect_locked(result: Result<vault_store::Vault, VaultError>) -> u64 {
    match result {
        Err(VaultError::Locked { remaining_secs }) => remaining_secs,
        Err(other) => panic!("预期 Locked，实际 {other}"),
        Ok(_) => panic!("预期 Locked，实际 Ok"),
    }
}

/// 把锁定到期时间改成过去，模拟「锁定时间已过」。
fn expire_lock(path: &Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute("UPDATE meta SET locked_until = '1' WHERE id = 1", [])
        .unwrap();
}

#[test]
fn fourth_failure_is_plain_error_fifth_locks() {
    let (tv, _rk) = bootstrapped();
    for _ in 0..4 {
        match unlock(tv.path(), "wrong") {
            Err(VaultError::InvalidInput(_)) => {}
            Err(other) => panic!("前 4 次应为普通错误，实际 {other}"),
            Ok(_) => panic!("前 4 次不应解锁成功"),
        }
    }
    let remaining = expect_locked(unlock(tv.path(), "wrong"));
    assert!(remaining > 0, "第 5 次应触发锁定");
}

#[test]
fn locked_vault_rejects_even_correct_password() {
    let (tv, _rk) = bootstrapped();
    for _ in 0..5 {
        let _ = unlock(tv.path(), "wrong");
    }
    let remaining = expect_locked(unlock(tv.path(), MASTER));
    assert!(remaining > 0, "锁定期内即便密码正确也应拒绝");
}

#[test]
fn lock_expires_and_counter_resets_after_successful_unlock() {
    let (tv, _rk) = bootstrapped();
    for _ in 0..5 {
        let _ = unlock(tv.path(), "wrong");
    }
    assert!(unlock(tv.path(), MASTER).is_err());

    expire_lock(tv.path());
    let _vault = unlock(tv.path(), MASTER).unwrap();

    let status = lock_status(tv.path()).unwrap();
    assert!(!status.locked, "成功解锁后不应再锁定");
    assert_eq!(status.failed_attempts, 0, "成功解锁后失败计数应清零");
}

#[test]
fn backoff_grows_and_caps_at_thirty_minutes() {
    let (tv, _rk) = bootstrapped();
    for _ in 0..4 {
        let _ = unlock(tv.path(), "wrong");
    }
    let expected_minutes = [5_u64, 10, 20, 30, 30];
    for minutes in expected_minutes {
        let remaining_secs = expect_locked(unlock(tv.path(), "wrong"));
        assert_eq!(
            remaining_secs,
            minutes * 60,
            "退避时长应为 {minutes} 分钟"
        );
        expire_lock(tv.path());
    }
}

#[test]
fn lock_status_reports_remaining_time() {
    let (tv, _rk) = bootstrapped();
    let before = lock_status(tv.path()).unwrap();
    assert!(!before.locked);
    assert_eq!(before.failed_attempts, 0);

    for _ in 0..5 {
        let _ = unlock(tv.path(), "wrong");
    }
    let after = lock_status(tv.path()).unwrap();
    assert!(after.locked);
    assert_eq!(after.failed_attempts, 5);
    assert!(
        after.remaining_secs > 4 * 60 && after.remaining_secs <= 5 * 60,
        "剩余时间应在 5 分钟内，实际 {} 秒",
        after.remaining_secs
    );
}

#[test]
fn many_failures_never_destroy_user_data() {
    let (tv, _rk) = bootstrapped();
    let vault = unlock(tv.path(), MASTER).unwrap();
    let id = vault.create_account(&sample_input()).unwrap();
    drop(vault);

    for _ in 0..20 {
        let _ = unlock(tv.path(), "wrong");
        expire_lock(tv.path());
    }

    let vault = unlock(tv.path(), MASTER).unwrap();
    assert_eq!(vault.list_accounts().unwrap().len(), 1, "数据必须完好");
    assert_eq!(
        vault.reveal_secret(&id, FieldType::LoginPassword).unwrap(),
        "LoginPw!234",
        "密文必须仍可解密"
    );
}

#[test]
fn recovery_key_still_works_while_locked() {
    let (tv, recovery_key) = bootstrapped();
    for _ in 0..5 {
        let _ = unlock(tv.path(), "wrong");
    }
    assert!(unlock(tv.path(), MASTER).is_err(), "应先处于锁定");

    recover(tv.path(), &recovery_key, "brand-new-master").unwrap();
    let vault = unlock(tv.path(), "brand-new-master").unwrap();
    let status = lock_status(tv.path()).unwrap();
    assert!(!status.locked, "恢复后应清除锁定");
    drop(vault);
}

#[test]
fn second_factor_verification_is_also_rate_limited() {
    let (tv, _rk) = bootstrapped();
    let _vault = unlock(tv.path(), MASTER).unwrap();
    for _ in 0..4 {
        assert!(!verify_master_password(tv.path(), "wrong").unwrap());
    }
    match verify_master_password(tv.path(), "wrong") {
        Err(VaultError::Locked { .. }) => {}
        other => panic!("二次验证第 5 次失败应触发锁定，实际 {other:?}"),
    }
    drop(_vault);
}

#[test]
fn correct_second_factor_resets_counter() {
    let (tv, _rk) = bootstrapped();
    let _vault = unlock(tv.path(), MASTER).unwrap();
    assert!(!verify_master_password(tv.path(), "wrong").unwrap());
    assert!(verify_master_password(tv.path(), MASTER).unwrap());
    assert_eq!(lock_status(tv.path()).unwrap().failed_attempts, 0);
    drop(_vault);
}
