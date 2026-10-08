//! 小工具：ID 生成与时间戳。

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use security_core::cipher::CryptoRng;

/// 生成 128-bit 随机 ID（Base64 URL-safe，无填充）。
pub(crate) fn new_id() -> String {
    URL_SAFE_NO_PAD.encode(CryptoRng::bytes(16))
}

/// 当前时间戳（epoch 毫秒字符串）。
pub(crate) fn now_millis() -> String {
    now_millis_u64().to_string()
}

/// 当前时间戳（epoch 毫秒数值，供退避锁定计算使用）。
pub(crate) fn now_millis_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
