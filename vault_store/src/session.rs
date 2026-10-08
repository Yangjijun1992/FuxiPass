//! 解锁会话与二次验证时效策略（T1.4 / T1.5）。
//!
//! 对应 PRD：
//! - §2.1：生物识别**只**解锁短期会话；**每 24 小时强制用主密码重新解锁一次**，
//!   避免长期使用后退化为「单因素」。
//! - §3.4.2：高敏感操作的二次验证会话默认 **2 分钟**内可复用，超时须重新验证。
//!
//! 时间由调用方以 `now_ms` 注入，便于测试且不依赖系统时钟。

use thiserror::Error;

/// 会话错误。
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SessionError {
    /// 距上次主密码验证已超过间隔，必须重新输入主密码（不可再用生物识别）。
    #[error("master password re-authentication required (bio unlock window expired)")]
    MasterReauthRequired,
}

/// 解锁方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMethod {
    /// 主密码（根解锁）。
    MasterPassword,
    /// 生物识别（快捷解锁，需在允许窗口内）。
    Biometric,
}

/// 时长策略。
#[derive(Debug, Clone, Copy)]
pub struct SessionPolicy {
    /// 高敏感操作二次验证会话时长（毫秒）。
    pub sensitive_action_ttl_ms: u64,
    /// 强制主密码重新解锁的间隔（毫秒）。
    pub master_reauth_interval_ms: u64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            sensitive_action_ttl_ms: 2 * 60 * 1000,
            master_reauth_interval_ms: 24 * 60 * 60 * 1000,
        }
    }
}

/// 当前解锁会话状态。
#[derive(Debug, Clone)]
pub struct Session {
    policy: SessionPolicy,
    last_master_auth_ms: u64,
    last_sensitive_auth_ms: Option<u64>,
}

impl Session {
    /// 以主密码建立会话（根解锁，重置 24h 计时）。
    pub fn start_with_master(now_ms: u64, policy: SessionPolicy) -> Self {
        Self {
            policy,
            last_master_auth_ms: now_ms,
            last_sensitive_auth_ms: None,
        }
    }

    /// 以生物识别建立/延续会话。
    ///
    /// 若距上次主密码验证已超过 `master_reauth_interval_ms`，**拒绝**并返回
    /// [`SessionError::MasterReauthRequired`]，此时必须回退到主密码。
    pub fn start_with_biometric(&self, now_ms: u64) -> Result<UnlockMethod, SessionError> {
        if self.requires_master_password(now_ms) {
            return Err(SessionError::MasterReauthRequired);
        }
        Ok(UnlockMethod::Biometric)
    }

    /// 是否必须用主密码重新解锁（生物识别不可用）。
    pub fn requires_master_password(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_master_auth_ms) >= self.policy.master_reauth_interval_ms
    }

    /// 距必须重新输入主密码还剩多少毫秒（已过期返回 0）。
    pub fn remaining_until_master_required(&self, now_ms: u64) -> u64 {
        self.policy
            .master_reauth_interval_ms
            .saturating_sub(now_ms.saturating_sub(self.last_master_auth_ms))
    }

    /// 标记刚刚完成一次二次验证（如揭示高敏感字段）。
    pub fn mark_sensitive_verified(&mut self, now_ms: u64) {
        self.last_sensitive_auth_ms = Some(now_ms);
    }

    /// 当前是否处于二次验证有效期内（高敏感操作可直接放行）。
    ///
    /// ⚠️ 该会话**不**重置 24h 主密码计时——二次验证不能替代根解锁。
    pub fn sensitive_action_allowed(&self, now_ms: u64) -> bool {
        match self.last_sensitive_auth_ms {
            None => false,
            Some(at) => now_ms.saturating_sub(at) < self.policy.sensitive_action_ttl_ms,
        }
    }

    /// 二次验证会话剩余毫秒（无效时返回 0）。
    pub fn sensitive_remaining(&self, now_ms: u64) -> u64 {
        match self.last_sensitive_auth_ms {
            None => 0,
            Some(at) => self
                .policy
                .sensitive_action_ttl_ms
                .saturating_sub(now_ms.saturating_sub(at)),
        }
    }

    /// 上次主密码验证时间（毫秒时间戳）。
    pub const fn last_master_auth_ms(&self) -> u64 {
        self.last_master_auth_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: u64 = 60 * 1000;
    const HOUR: u64 = 60 * MINUTE;

    #[test]
    fn biometric_works_within_master_window() {
        let session = Session::start_with_master(0, SessionPolicy::default());
        assert!(!session.requires_master_password(HOUR));
        assert_eq!(
            session.start_with_biometric(HOUR).unwrap(),
            UnlockMethod::Biometric
        );
    }

    #[test]
    fn biometric_is_rejected_after_twenty_four_hours() {
        let session = Session::start_with_master(0, SessionPolicy::default());
        assert!(session.requires_master_password(24 * HOUR));
        assert_eq!(
            session.start_with_biometric(24 * HOUR),
            Err(SessionError::MasterReauthRequired)
        );
    }

    #[test]
    fn master_unlock_resets_the_twenty_four_hour_clock() {
        let policy = SessionPolicy::default();
        let _first = Session::start_with_master(0, policy);
        // 23 小时后重新用主密码解锁
        let session = Session::start_with_master(23 * HOUR, policy);
        // 再过 23 小时（距首次已 46 小时）仍可生物识别，因为主密码在 23h 时验证过
        assert_eq!(
            session.start_with_biometric(46 * HOUR).unwrap(),
            UnlockMethod::Biometric
        );
    }

    #[test]
    fn sensitive_action_expires_after_two_minutes() {
        let mut session = Session::start_with_master(0, SessionPolicy::default());
        assert!(!session.sensitive_action_allowed(0), "未验证时应拒绝");
        session.mark_sensitive_verified(0);
        assert!(session.sensitive_action_allowed(MINUTE + 59 * 1000));
        assert!(
            !session.sensitive_action_allowed(2 * MINUTE),
            "2 分钟后应失效"
        );
    }

    #[test]
    fn sensitive_verification_does_not_extend_master_window() {
        let mut session = Session::start_with_master(0, SessionPolicy::default());
        session.mark_sensitive_verified(23 * HOUR);
        // 二次验证不重置 24h 计时
        assert!(session.requires_master_password(24 * HOUR));
    }

    #[test]
    fn remaining_time_is_reported() {
        let session = Session::start_with_master(0, SessionPolicy::default());
        assert_eq!(session.remaining_until_master_required(2 * HOUR), 22 * HOUR);
        assert_eq!(session.remaining_until_master_required(25 * HOUR), 0);
    }
}
