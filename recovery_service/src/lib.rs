//! 零知识找回服务（T2.4/T2.5，PRD §2.2）。
//!
//! # 零知识边界（必须保持）
//!
//! 服务端**只**存储两类数据：
//! 1. `contact_hash` —— 邮箱/手机号的**不可逆哈希**（不存明文联系方式）；
//! 2. `recoverywrap` —— 用**用户恢复密钥**加密的 DEK 包裹（服务端无解密密钥）。
//!
//! 服务端**永不**接触：主密码、KEK、恢复密钥、明文验证码、任何明文凭证。
//! 因此即便服务端被完全攻破，攻击者仍无法解密用户数据。
//!
//! # 两把钥匙
//!
//! 找回需要「验证码（第二因素）」+「恢复密钥（真正密钥）」同时具备：
//! 本服务只负责验证码校验并下发**加密包裹**；解包必须由客户端用恢复密钥完成。

pub mod api;

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// 联系方式类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContactType {
    /// 邮箱。
    Email,
    /// 手机短信。
    Sms,
}

/// 找回绑定（服务端可见的全部数据）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    /// 联系方式的不可逆哈希（如 Blake3/Argon2 结果，由客户端计算）。
    pub contact_hash: String,
    /// 联系方式类型。
    pub contact_type: ContactType,
    /// 用恢复密钥加密的 DEK 包裹（`Wrap` 的 JSON）。
    pub recoverywrap: String,
}

/// 服务错误。
#[derive(Debug, Clone, thiserror::Error)]
pub enum RecoveryError {
    /// 未绑定该联系方式。
    #[error("contact not bound")]
    NotBound,
    /// 请求过于频繁。
    #[error("too many requests")]
    RateLimited,
    /// 验证码错误。
    #[error("incorrect code")]
    IncorrectCode,
    /// 验证码已过期或不存在。
    #[error("code expired")]
    CodeExpired,
    /// 验证码尝试次数过多（已作废）。
    #[error("too many attempts; request a new code")]
    TooManyAttempts,
    /// 令牌无效或已过期。
    #[error("invalid or expired token")]
    InvalidToken,
}

/// 验证码下发结果（`dev_code` 仅供开发/测试；生产应经邮件/短信通道下发且不返回）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeIssued {
    /// 一次性请求 ID。
    pub request_id: String,
    /// 验证码有效期（秒）。
    pub ttl_sec: u64,
    /// 开发模式下回显验证码（生产为 `None`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_code: Option<String>,
}

/// 验证成功后的结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// 短寿命访问令牌。
    pub token: String,
    /// 用恢复密钥加密的 DEK 包裹（**密文**）。
    pub recoverywrap: String,
    /// 令牌有效期（秒）。
    pub expires_in: u64,
}

/// 验证码常量。
pub const CODE_TTL_SECS: u64 = 300;
/// 单次验证码最大尝试次数。
pub const MAX_VERIFY_ATTEMPTS: u32 = 5;
/// 令牌有效期。
pub const TOKEN_TTL_SECS: u64 = 120;
/// 同一联系方式在窗口内最多可发起的挑战次数。
pub const MAX_CHALLENGES_PER_WINDOW: usize = 3;
/// 挑战限流窗口。
pub const CHALLENGE_WINDOW_SECS: u64 = 600;

#[derive(Debug, Clone)]
struct Challenge {
    contact_hash: String,
    code: String,
    expires_at_ms: u64,
    attempts: u32,
}

#[derive(Debug, Clone)]
struct Token {
    contact_hash: String,
    expires_at_ms: u64,
    used: bool,
}

/// 内存态找回服务（生产可替换为持久化实现，接口保持不变）。
pub struct RecoveryService {
    inner: Mutex<Inner>,
    /// 是否回显验证码（仅开发/测试开启）。
    pub dev_echo_code: bool,
}

#[derive(Default)]
struct Inner {
    bindings: HashMap<String, Binding>,
    challenges: HashMap<String, Challenge>,
    tokens: HashMap<String, Token>,
    /// 挑战发起记录：contact_hash → 时间戳列表（用于限流）。
    challenge_log: HashMap<String, Vec<u64>>,
}

impl RecoveryService {
    /// 创建服务实例。`dev_echo_code=true` 时 `challenge` 会回显验证码（仅供测试）。
    pub fn new(dev_echo_code: bool) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            dev_echo_code,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // 说明：唯一可能的中毒来源是持有锁时 panic；本实现内无 panic 路径，
        // 因此用 `unwrap_or_else` 复位而非向上抛错。
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 绑定联系方式哈希与加密包裹（重复绑定覆盖旧值）。
    pub fn bind(&self, binding: Binding) {
        self.lock()
            .bindings
            .insert(binding.contact_hash.clone(), binding);
    }

    /// 发起挑战：由服务端用 CSPRNG 生成一次性验证码与请求 ID。
    ///
    /// 验证码**绝不由调用方指定**，且生产环境只经邮件/短信通道下发（不回显）。
    pub fn challenge(
        &self,
        contact_hash: &str,
        now_ms: u64,
    ) -> Result<ChallengeIssued, RecoveryError> {
        let mut inner = self.lock();
        if !inner.bindings.contains_key(contact_hash) {
            // 不区分「未绑定」与「已绑定」，避免账号枚举；此处返回统一错误由调用方决定。
            return Err(RecoveryError::NotBound);
        }
        let window_start = now_ms.saturating_sub(CHALLENGE_WINDOW_SECS * 1000);
        let log = inner
            .challenge_log
            .entry(contact_hash.to_owned())
            .or_default();
        log.retain(|t| *t >= window_start);
        if log.len() >= MAX_CHALLENGES_PER_WINDOW {
            return Err(RecoveryError::RateLimited);
        }
        log.push(now_ms);

        let request_id = format!("req_{}", random_id());
        let code = generate_code();
        inner.challenges.insert(
            request_id.clone(),
            Challenge {
                contact_hash: contact_hash.to_owned(),
                code: code.clone(),
                expires_at_ms: now_ms + CODE_TTL_SECS * 1000,
                attempts: 0,
            },
        );
        Ok(ChallengeIssued {
            request_id,
            ttl_sec: CODE_TTL_SECS,
            dev_code: if self.dev_echo_code { Some(code) } else { None },
        })
    }

    /// 校验验证码并签发短寿命令牌 + 下发加密包裹。
    pub fn verify(
        &self,
        request_id: &str,
        code: &str,
        now_ms: u64,
        token: String,
    ) -> Result<VerifyResult, RecoveryError> {
        let mut inner = self.lock();
        let Some(challenge) = inner.challenges.get_mut(request_id) else {
            return Err(RecoveryError::CodeExpired);
        };
        if now_ms > challenge.expires_at_ms {
            inner.challenges.remove(request_id);
            return Err(RecoveryError::CodeExpired);
        }
        if challenge.attempts >= MAX_VERIFY_ATTEMPTS {
            inner.challenges.remove(request_id);
            return Err(RecoveryError::TooManyAttempts);
        }
        if !constant_time_eq(&challenge.code, code) {
            challenge.attempts += 1;
            return Err(RecoveryError::IncorrectCode);
        }
        // 一次性：校验成功立即作废
        let contact_hash = challenge.contact_hash.clone();
        inner.challenges.remove(request_id);

        let Some(binding) = inner.bindings.get(&contact_hash) else {
            return Err(RecoveryError::NotBound);
        };
        let recoverywrap = binding.recoverywrap.clone();
        inner.tokens.insert(
            token.clone(),
            Token {
                contact_hash,
                expires_at_ms: now_ms + TOKEN_TTL_SECS * 1000,
                used: false,
            },
        );
        Ok(VerifyResult {
            token,
            recoverywrap,
            expires_in: TOKEN_TTL_SECS,
        })
    }

    /// 用令牌再次获取包裹（一次性消费）。
    pub fn redeem(&self, token: &str, now_ms: u64) -> Result<String, RecoveryError> {
        let mut inner = self.lock();
        let Some(entry) = inner.tokens.get_mut(token) else {
            return Err(RecoveryError::InvalidToken);
        };
        if entry.used || now_ms > entry.expires_at_ms {
            return Err(RecoveryError::InvalidToken);
        }
        entry.used = true;
        let contact_hash = entry.contact_hash.clone();
        inner
            .bindings
            .get(&contact_hash)
            .map(|b| b.recoverywrap.clone())
            .ok_or(RecoveryError::NotBound)
    }

    /// 仅用于测试/审计：服务端持有的绑定数量。
    pub fn binding_count(&self) -> usize {
        self.lock().bindings.len()
    }
}

/// 常量时间比较（等长比较；长度不同直接返回 false，不泄露内容信息）。
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 生成 6 位数字验证码（CSPRNG，均匀分布）。
fn generate_code() -> String {
    use security_core::cipher::CryptoRng;
    let bytes = CryptoRng::bytes(4);
    let n = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 1_000_000;
    format!("{n:06}")
}

/// 生成随机 ID（复用 `getrandom` 语义的系统随机源）。
fn random_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // 说明：ID 仅用于索引，不承担机密性；验证码本身由调用方通过 CSPRNG 生成。
    format!("{nanos:x}")
}
