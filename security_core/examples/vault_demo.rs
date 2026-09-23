//! 最小可运行示例：初始化密钥库 → 打印 DEK 包裹 JSON → 验证解锁。
//!
//! 用法：`cargo run --example vault_demo`

use security_core::{
    change_master_password, derive_kek, generate_dek, generate_recovery_key, unwrap_dek,
    unwrap_dek_via_recovery, wrap_dek, wrap_dek_via_recovery, KdfParams, RecoveryKey,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = KdfParams::with_random_salt();
    let pw = b"correct horse battery staple";
    let kek = derive_kek(pw, &params)?;
    let dek = generate_dek();
    let recovery = generate_recovery_key();

    let dekwrap = wrap_dek(&kek, &dek, Some(params.clone()))?;
    let recovery_wrap = wrap_dek_via_recovery(&recovery, &dek)?;

    println!("== DEK 包裹 (JSON) ==");
    println!("{}", serde_json::to_string_pretty(&dekwrap)?);
    println!("\n== Recovery 包裹 (JSON) ==");
    println!("{}", serde_json::to_string_pretty(&recovery_wrap)?);
    println!("\nRecoveryKey 显示格式: {}", recovery.to_display());

    // 解锁验证
    let unlocked = unwrap_dek(&kek, &dekwrap)?;
    assert_eq!(unlocked.as_bytes(), dek.as_bytes());
    println!("\n[OK] 解锁还原 DEK 一致");

    // 恢复验证
    let recovered = unwrap_dek_via_recovery(&RecoveryKey::from_display(&recovery.to_display())?,
        &recovery_wrap)?;
    assert_eq!(recovered.as_bytes(), dek.as_bytes());
    println!("[OK] RecoveryKey 显示→解析→解包还原 DEK 一致");

    // 改密验证（DEK 不变）
    let new_pw = b"a brand new master password";
    let new_params = KdfParams::with_random_salt();
    let new_dekwrap = change_master_password(&kek, &dekwrap, new_pw, &new_params)?;
    let new_kek = derive_kek(new_pw, &new_params)?;
    let dek_after = unwrap_dek(&new_kek, &new_dekwrap)?;
    assert_eq!(dek_after.as_bytes(), dek.as_bytes());
    println!("[OK] 改主密码后 DEK 保持一致（无需重加密全量）");

    Ok(())
}
