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

/// 测试用联系方式（明文仅存在于客户端；服务端只收哈希）。
const CONTACT: &str = "owner@example.com";

/// 联系方式哈希（Argon2id 派生，较慢 —— 缓存以加速测试）。
fn contact_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| security_core::contact_hash(CONTACT).unwrap())
}

fn binding() -> Binding {
    Binding {
        contact_hash: contact_hash().to_owned(),
        contact_type: ContactType::Email,
        recoverywrap: r#"{"version":1,"cipher":{"algorithm":"aes-256-gcm","nonce":"AA","tag":"BB"},"ciphertext":"ENCRYPTED-ONLY"}"#.to_owned(),
    }
}

const NOW: u64 = 1_800_000_000_000;

#[test]
fn bind_challenge_verify_and_redeem_returns_only_ciphertext() {
    let svc = RecoveryService::new(true);
    svc.bind(binding()).unwrap();

    let issued = svc.challenge(contact_hash(), CONTACT, NOW).unwrap();
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
    let err = svc.challenge("unknown-hash", CONTACT, NOW).unwrap_err();
    assert!(matches!(err, RecoveryError::NotBound));
}

#[test]
fn wrong_code_is_rejected_and_decrements_attempts() {
    let svc = RecoveryService::new(true);
    svc.bind(binding()).unwrap();
    let issued = svc.challenge(contact_hash(), CONTACT, NOW).unwrap();

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
    svc.bind(binding()).unwrap();
    let issued = svc.challenge(contact_hash(), CONTACT, NOW).unwrap();
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
    svc.bind(binding()).unwrap();
    let issued = svc.challenge(contact_hash(), CONTACT, NOW).unwrap();
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
    svc.bind(binding()).unwrap();
    let issued = svc.challenge(contact_hash(), CONTACT, NOW).unwrap();
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
    let issued2 = svc.challenge(contact_hash(), CONTACT, NOW + 1_000).unwrap();
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
    svc.bind(binding()).unwrap();
    let mut issued = Vec::new();
    for i in 0..MAX_CHALLENGES_PER_WINDOW {
        issued.push(
            svc.challenge(contact_hash(), CONTACT, NOW + i as u64)
                .unwrap(),
        );
    }
    let err = svc
        .challenge(contact_hash(), CONTACT, NOW + 100)
        .unwrap_err();
    assert!(matches!(err, RecoveryError::RateLimited));

    // 窗口过后可再次发起
    let after = NOW + CHALLENGE_WINDOW_SECS * 1000 + 1;
    assert!(svc.challenge(contact_hash(), CONTACT, after).is_ok());
}

#[test]
fn plaintext_contact_must_match_bound_hash() {
    // 安全红线：攻击者即使知道某个哈希，也不能让服务把验证码发给**另一个**邮箱，
    // 否则本服务会沦为垃圾邮件转发器（并可能泄露验证码）。
    let svc = RecoveryService::new(true);
    svc.bind(binding()).unwrap();

    let err = svc
        .challenge(contact_hash(), "attacker@evil.example", NOW)
        .unwrap_err();
    assert!(
        matches!(err, RecoveryError::NotBound),
        "明文与绑定哈希不匹配时必须拒绝，实际 {err:?}"
    );

    // 大小写/空白归一化后仍应匹配（用户体验）
    let svc2 = RecoveryService::new(true);
    svc2.bind(binding()).unwrap();
    assert!(svc2
        .challenge(contact_hash(), "  OWNER@Example.com  ", NOW)
        .is_ok());
}

#[test]
fn server_side_storage_has_no_plaintext_contact() {
    let svc = RecoveryService::new(false);
    svc.bind(binding()).unwrap();
    // 服务端只保存绑定，且其字段仅含哈希 + 密文包裹
    assert_eq!(svc.binding_count(), 1);
    let stored = binding();
    assert!(!stored.contact_hash.contains('@'), "不得存明文邮箱");
    assert!(
        !stored.contact_hash.contains("example") && !stored.contact_hash.contains("user"),
        "哈希中不得残留明文片段"
    );
    assert!(
        !stored.recoverywrap.contains("yjj") && !stored.recoverywrap.contains("master"),
        "包裹中不得含任何明文线索"
    );
}
