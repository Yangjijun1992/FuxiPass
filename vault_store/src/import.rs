//! 历史旧文本智能导入（T2.6）：把非结构化文本解析为候选账号。
//!
//! 支持常见的手写/记事本格式：
//! - 标签式多行：`淘宝` / `账号：zhangsan` / `登录密码：123456` / `支付密码：…`
//! - 单行内联：`淘宝 账号：zhangsan 密码：123456`
//! - 括号平台名：`[淘宝]` / `【淘宝】`（括号行本身不会被当成账号）
//! - 无标签三行启发式：平台 / 账号 / 密码
//! - 多段以空行、`---`/`===`/`***` 或 `#` 注释行分隔
//!
//! 字段级敏感度映射（PRD §3.1）：
//! `密码` → 登录密码；`二级密码`/`安全码` → 二级密码；
//! `支付密码`/`交易密码`/`银行卡密码` → 支付密码；`密钥`/`api key`/`私钥` → API Key。

use serde::{Deserialize, Serialize};

use crate::error::VaultError;
use crate::import_parse::{bracket_app, extract_pairs, split_blocks, Field};
use crate::models::{AccountInput, Importance};
use crate::Vault;

/// 解析出的候选账号（字段可空，附解析告警，供人工确认）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportCandidate {
    /// 应用/网站名。
    pub app_name: Option<String>,
    /// 账号/用户名。
    pub username: Option<String>,
    /// 登录密码。
    pub login_password: Option<String>,
    /// 二级密码。
    #[serde(default)]
    pub secondary_password: Option<String>,
    /// 支付密码。
    #[serde(default)]
    pub payment_password: Option<String>,
    /// API Key / 密钥 / 私钥。
    #[serde(default)]
    pub api_key: Option<String>,
    /// 网址。
    pub url: Option<String>,
    /// 备注。
    pub notes: Option<String>,
    /// 解析告警（如缺少平台名或密码）。
    pub issues: Vec<String>,
}

fn empty_candidate() -> ImportCandidate {
    // 保留显式构造以便新增字段时强制审查。
    ImportCandidate {
        app_name: None,
        username: None,
        login_password: None,
        secondary_password: None,
        payment_password: None,
        api_key: None,
        url: None,
        notes: None,
        issues: Vec::new(),
    }
}

fn slot_of(candidate: &mut ImportCandidate, field: Field) -> &mut Option<String> {
    match field {
        Field::App => &mut candidate.app_name,
        Field::Username => &mut candidate.username,
        Field::Password => &mut candidate.login_password,
        Field::SecondaryPassword => &mut candidate.secondary_password,
        Field::PaymentPassword => &mut candidate.payment_password,
        Field::ApiKey => &mut candidate.api_key,
        Field::Url => &mut candidate.url,
        Field::Notes => &mut candidate.notes,
    }
}

fn has_any_password(candidate: &ImportCandidate) -> bool {
    candidate.login_password.is_some()
        || candidate.secondary_password.is_some()
        || candidate.payment_password.is_some()
        || candidate.api_key.is_some()
}

fn parse_block(block: &str) -> ImportCandidate {
    let mut cand = empty_candidate();
    let mut unlabeled: Vec<String> = Vec::new();

    for line in block.lines() {
        let has_bracket = bracket_app(line).is_some();
        if let Some(app) = bracket_app(line) {
            if cand.app_name.is_none() {
                cand.app_name = Some(app);
            }
        }
        let (pairs, prefix) = extract_pairs(line);
        // 括号平台名行本身不作为账号/噪声参与后续启发式。
        if !prefix.is_empty() && !has_bracket {
            unlabeled.push(prefix);
        }
        for (field, value) in pairs {
            let slot = slot_of(&mut cand, field);
            if slot.is_none() {
                *slot = Some(value);
            }
        }
    }

    if cand.app_name.is_none() {
        if let Some(first) = unlabeled.first() {
            cand.app_name = Some(first.clone());
            unlabeled.remove(0);
        } else if let Some(host) = cand.url.as_deref().and_then(host_from_url) {
            cand.app_name = Some(host);
        }
    }

    if !has_any_password(&cand) && !unlabeled.is_empty() {
        cand.username = Some(unlabeled.remove(0));
        cand.issues
            .push("未识别到密码标签，已按顺序猜测账号".to_owned());
    }
    if !has_any_password(&cand) && !unlabeled.is_empty() {
        cand.login_password = Some(unlabeled.remove(0));
        cand.issues
            .push("未识别到密码标签，已按顺序猜测密码".to_owned());
    }

    if cand.app_name.is_none() {
        cand.issues.push("缺少平台/网站名".to_owned());
    }
    if !has_any_password(&cand) {
        cand.issues.push("缺少密码".to_owned());
    }
    cand
}

fn host_from_url(url: &str) -> Option<String> {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = without_scheme.split('/').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

/// 把整段文本解析为候选账号列表。
pub fn parse_notes(text: &str) -> Vec<ImportCandidate> {
    split_blocks(text)
        .into_iter()
        .map(|b| parse_block(&b))
        .filter(|c| {
            c.app_name.is_some()
                || c.username.is_some()
                || has_any_password(c)
                || c.notes.is_some()
        })
        .collect()
}

/// 批量导入结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportOutcome {
    /// 成功导入数量。
    pub imported: usize,
    /// 失败项（序号 + 原因）。
    pub failed: Vec<String>,
}

impl Vault {
    /// 批量导入候选账号（逐条写入；单条失败不阻断其余条目）。
    pub fn import_candidates(&self, candidates: &[ImportCandidate]) -> ImportOutcome {
        let mut imported = 0_usize;
        let mut failed = Vec::new();
        for (i, candidate) in candidates.iter().enumerate() {
            match candidate_to_input(candidate).and_then(|input| self.create_account(&input)) {
                Ok(_) => imported += 1,
                Err(e) => failed.push(format!("#{}: {e}", i + 1)),
            }
        }
        let _ = self.record_audit("import_candidates", None, None);
        ImportOutcome { imported, failed }
    }
}

/// 把候选转换为入库输入，并做必填校验。
pub fn candidate_to_input(candidate: &ImportCandidate) -> Result<AccountInput, VaultError> {
    let input = AccountInput {
        app_name: candidate.app_name.clone().unwrap_or_default(),
        url: candidate.url.clone(),
        username: candidate.username.clone(),
        notes: candidate.notes.clone(),
        importance: Importance::Common,
        login_password: candidate.login_password.clone(),
        secondary_password: candidate.secondary_password.clone(),
        payment_password: candidate.payment_password.clone(),
        api_key: candidate.api_key.clone(),
    };
    input.validate()?;
    Ok(input)
}
