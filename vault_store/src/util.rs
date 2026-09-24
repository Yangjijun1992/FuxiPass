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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(|_| String::from("0"), |d| d.as_millis().to_string())
}
