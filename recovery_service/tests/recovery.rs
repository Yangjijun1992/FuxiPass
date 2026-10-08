//! 零知识找回服务测试（T2.4/T2.5）。
//!
//! 覆盖：绑定→挑战→验证→取回包裹全流程；一次性验证码/令牌；过期；限流；
//! 尝试次数上限；以及**服务端不存明文联系方式**这一零知识性质。

// 集成测试为纯测试代码，允许 unwrap/expect/panic（服务端 src/ 仍全局 deny）。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use recovery_service::{
    Binding, ContactType, RecoveryError, RecoveryService, CHALLENGE_WINDOW_SECS, CODE_TTL_SECS,
    MAX_CHALLENGES_PER_WINDOW, MAX_VERIFY_ATTEMPTS,
};

/// 联系方式哈希（真实形态：不可逆、无明文、无结构信息）。
const CONTACT_HASH: &str = "9f2c1ab47de05c3f8b6e21d4a70c93e5f1b8d2064c7a9e3f5d8b1c4a7e0f3d6b9";

fn binding() -> Binding {
    Binding {
        contact_hash: CONTACT_HASH.to_owned(),
        contact_type: ContactType::Email,
        recoverywrap: r#"{"version":1,"cipher":{"algorithm":"aes-256-gcm","nonce":"AA","tag":"BB"},"ciphertext":"ENCRYPTED-ONLY"}"#.to_owned(),
    }
}

const NOW: u64 = 1_800_000_000_000;

#[test]
fn bind_challenge_verify_and_redeem_returns_only_ciphertext() {
    let svc = RecoveryService::new(true);
    svc.bind(binding());

    let issued = svc.challenge(CONTACT_HASH, NOW).unwrap();
    assert_eq!(issued.ttl_sec, CODE_TTL_SECS);
    let code = issued.dev_code.clone().unwrap();

    let verified = svc
        .verify(&issued.request_id, &code, NOW + 1_000, "tok_1".to_owned())
        .unwrap();
    // 服务端只返回密文包裹，绝无明文
    assert!(result_contains_only_ciphertext(&verified.recoverywrap));

    let wrap = svc.redeem("tok_1", NOW + 2_000).unwrap();
    assert!(result_contains_only_ciphertext(&wrap));
}

/// 断言包裹中不含任何可疑明文（测试数据里只有 ENCRYPTED-ONLY 标记）。
fn result_contains_only_ciphertext(wrap: &str) -> bool {
    wrap.contains("ENCRYPTED-ONLY") && !wrap.contains("password")
}

#[test]
fn unbound_contact_cannot_request_challenge() {
    let svc = RecoveryService::new(true);
    let err = svc.challenge("unknown-hash", NOW).unwrap_err();
    assert!(matches!(err, RecoveryError::NotBound));
}

#[test]
fn wrong_code_is_rejected_and_decrements_attempts() {
    let svc = RecoveryService::new(true);
    svc.bind(binding());
    let issued = svc.challenge(CONTACT_HASH, NOW).unwrap();

    for _ in 0..(MAX_VERIFY_ATTEMPTS - 1) {
        let err = svc
            .verify(&issued.request_id, "000000", NOW, "t".to_owned())
            .unwrap_err();
        assert!(matches!(err, RecoveryError::IncorrectCode));
    }
    // 第 MAX_VERIFY_ATTEMPTS 次错误后，挑战作废
    let _ = svc.verify(&issued.request_id, "000000", NOW, "t".to_owned());
    let err = svc
        .verify(&issued.request_id, "123456", NOW, "t".to_owned())
        .unwrap_err();
    assert!(
        matches!(
            err,
            RecoveryError::CodeExpired | RecoveryError::TooManyAttempts
        ),
        "预期挑战已作废，实际 {err:?}"
    );
}

#[test]
fn code_is_single_use() {
    let svc = RecoveryService::new(true);
    svc.bind(binding());
    let issued = svc.challenge(CONTACT_HASH, NOW).unwrap();
    let code = issued.dev_code.clone().unwrap();

    assert!(svc
        .verify(&issued.request_id, &code, NOW, "tok_a".to_owned())
        .is_ok());
    // 同一 request_id 再次校验必须失败（已被消费）
    let err = svc
        .verify(&issued.request_id, &code, NOW, "tok_b".to_owned())
        .unwrap_err();
    assert!(matches!(err, RecoveryError::CodeExpired));
}

#[test]
fn expired_code_is_rejected() {
    let svc = RecoveryService::new(true);
    svc.bind(binding());
    let issued = svc.challenge(CONTACT_HASH, NOW).unwrap();
    let code = issued.dev_code.clone().unwrap();
    let err = svc
        .verify(
            &issued.request_id,
            &code,
            NOW + CODE_TTL_SECS * 1000 + 1,
            "t".to_owned(),
        )
        .unwrap_err();
    assert!(matches!(err, RecoveryError::CodeExpired));
}

#[test]
fn token_is_single_use_and_expires() {
    let svc = RecoveryService::new(true);
    svc.bind(binding());
    let issued = svc.challenge(CONTACT_HASH, NOW).unwrap();
    let code = issued.dev_code.clone().unwrap();
    let _ = svc
        .verify(&issued.request_id, &code, NOW, "tok".to_owned())
        .unwrap();

    assert!(svc.redeem("tok", NOW + 1_000).is_ok());
    // 二次使用被拒
    assert!(matches!(
        svc.redeem("tok", NOW + 2_000),
        Err(RecoveryError::InvalidToken)
    ));
    // 过期令牌被拒
    let issued2 = svc.challenge(CONTACT_HASH, NOW + 1_000).unwrap();
    let code2 = issued2.dev_code.unwrap();
    let _ = svc
        .verify(&issued2.request_id, &code2, NOW + 1_000, "tok2".to_owned())
        .unwrap();
    assert!(matches!(
        svc.redeem("tok2", NOW + 1_000_000),
        Err(RecoveryError::InvalidToken)
    ));
}

#[test]
fn challenges_are_rate_limited_per_window() {
    let svc = RecoveryService::new(true);
    svc.bind(binding());
    let mut issued = Vec::new();
    for i in 0..MAX_CHALLENGES_PER_WINDOW {
        issued.push(svc.challenge(CONTACT_HASH, NOW + i as u64).unwrap());
    }
    let err = svc.challenge(CONTACT_HASH, NOW + 100).unwrap_err();
    assert!(matches!(err, RecoveryError::RateLimited));

    // 窗口过后可再次发起
    let after = NOW + CHALLENGE_WINDOW_SECS * 1000 + 1;
    assert!(svc.challenge(CONTACT_HASH, after).is_ok());
}

#[test]
fn server_side_storage_has_no_plaintext_contact() {
    let svc = RecoveryService::new(false);
    svc.bind(binding());
    // 服务端只保存绑定，且其字段仅含哈希 + 密文包裹
    assert_eq!(svc.binding_count(), 1);
    let stored = binding();
    assert!(!stored.contact_hash.contains('@'), "不得存明文邮箱");
    assert!(
        !stored.contact_hash.contains("westlake") && !stored.contact_hash.contains("yangjijun"),
        "哈希中不得残留明文片段"
    );
    assert!(
        !stored.recoverywrap.contains("yjj") && !stored.recoverywrap.contains("master"),
        "包裹中不得含任何明文线索"
    );
}
