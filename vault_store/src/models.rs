//! 领域模型：账号卡片、字段分级、审计条目。
//!
//! 与 docs/04 的表结构对应；序列化后直接用于 Web API 的 JSON 载荷。

use serde::{Deserialize, Serialize};

/// 重要度分类（PRD §3.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Importance {
    /// 常用。
    Common,
    /// 金融银行。
    Finance,
    /// 低频备用。
    LowFrequency,
    /// 社交。
    Social,
}

impl Importance {
    /// 数据库存储字面量。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Common => "common",
            Self::Finance => "finance",
            Self::LowFrequency => "low_frequency",
            Self::Social => "social",
        }
    }

    /// 从存储字面量解析（未知值回退为 `Common`）。
    pub fn parse(s: &str) -> Self {
        match s {
            "finance" => Self::Finance,
            "low_frequency" => Self::LowFrequency,
            "social" => Self::Social,
            _ => Self::Common,
        }
    }
}

/// 高敏感/普通密码字段类型（PRD §3.1 字段表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// 登录密码（级别：高）。
    LoginPassword,
    /// 二级密码（级别：极高，需二次验证）。
    SecondaryPassword,
    /// 支付密码（级别：极高，需二次验证）。
    PaymentPassword,
    /// API Key（级别：极高，需二次验证）。
    ApiKey,
    /// 密钥 / 区块链私钥（级别：极高，需二次验证）。
    PrivateKey,
    /// TOTP 密钥。
    Totp,
}

impl FieldType {
    /// 数据库存储字面量。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LoginPassword => "login_password",
            Self::SecondaryPassword => "secondary_password",
            Self::PaymentPassword => "payment_password",
            Self::ApiKey => "api_key",
            Self::PrivateKey => "private_key",
            Self::Totp => "totp",
        }
    }

    /// 从存储字面量解析。
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "login_password" => Some(Self::LoginPassword),
            "secondary_password" => Some(Self::SecondaryPassword),
            "payment_password" => Some(Self::PaymentPassword),
            "api_key" => Some(Self::ApiKey),
            "private_key" => Some(Self::PrivateKey),
            "totp" => Some(Self::Totp),
            _ => None,
        }
    }

    /// 是否属于「极高」敏感级别（查看/复制需二次验证，PRD §3.4.2）。
    pub const fn requires_second_factor(self) -> bool {
        match self {
            Self::SecondaryPassword | Self::PaymentPassword | Self::ApiKey | Self::PrivateKey => true,
            Self::LoginPassword | Self::Totp => false,
        }
    }

    /// 用于审计日志的字段类别名。
    pub const fn category(self) -> &'static str {
        match self {
            Self::LoginPassword => "login_password",
            Self::SecondaryPassword => "secondary_password",
            Self::PaymentPassword => "payment_password",
            Self::ApiKey => "api_key",
            Self::PrivateKey => "private_key",
            Self::Totp => "totp",
        }
    }
}

/// 新建/更新账号卡片的输入。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInput {
    /// 应用/网站名称（必填）。
    pub app_name: String,
    /// 网址 / 应用包名。
    #[serde(default)]
    pub url: Option<String>,
    /// 账号 / 用户名。
    #[serde(default)]
    pub username: Option<String>,
    /// 备注（含密保答案等，级别：高）。
    #[serde(default)]
    pub notes: Option<String>,
    /// 重要度分类。
    pub importance: Importance,
    /// 登录密码。
    #[serde(default)]
    pub login_password: Option<String>,
    /// 二级密码。
    #[serde(default)]
    pub secondary_password: Option<String>,
    /// 支付密码。
    #[serde(default)]
    pub payment_password: Option<String>,
    /// API Key / 私钥。
    #[serde(default)]
    pub api_key: Option<String>,
}

impl AccountInput {
    /// 校验必填项。
    pub fn validate(&self) -> Result<(), crate::VaultError> {
        if self.app_name.trim().is_empty() {
            return Err(crate::VaultError::InvalidInput(
                "app_name is required".to_owned(),
            ));
        }
        Ok(())
    }
}

/// 列表/检索用的账号摘要（不含任何密码明文）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSummary {
    /// 卡片 ID。
    pub id: String,
    /// 应用/网站名（解密后返回）。
    pub app_name: String,
    /// 网址（解密后返回）。
    pub url: Option<String>,
    /// 账号（解密后返回）。
    pub username: Option<String>,
    /// 重要度。
    pub importance: Importance,
    /// 该卡片包含的高敏感字段类型。
    pub field_types: Vec<FieldType>,
    /// 更新时间。
    pub updated_at: String,
}

/// 高敏感字段的脱敏视图（不含明文）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFieldView {
    /// 字段类型。
    pub field_type: FieldType,
    /// 脱敏预览（如 `88****`）。
    pub masked_preview: String,
    /// 是否需要二次验证。
    pub requires_second_factor: bool,
}

/// 账号详情（备注 + 高敏感字段脱敏视图）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDetail {
    /// 摘要信息。
    #[serde(flatten)]
    pub summary: AccountSummary,
    /// 备注明文（级别：高，仅解锁且非极高字段时返回）。
    pub notes: Option<String>,
    /// 高敏感字段脱敏列表。
    pub secrets: Vec<SecretFieldView>,
}

/// 审计日志条目（不含任何明文）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// 时间戳（epoch millis 字符串）。
    pub ts: String,
    /// 操作类型。
    pub operation: String,
    /// 字段类别（若有）。
    pub field_category: Option<String>,
    /// 关联账号 ID（若有）。
    pub account_id: Option<String>,
}

/// 对明文生成脱敏预览（如 `88****`）。
pub fn masked_preview(plaintext: &str) -> String {
    let chars: Vec<char> = plaintext.chars().collect();
    if chars.len() <= 2 {
        return "*".repeat(chars.len().max(1));
    }
    let visible: String = chars.iter().take(2).collect();
    let hidden = (chars.len() - 2).min(6);
    format!("{visible}{}", "*".repeat(hidden))
}
