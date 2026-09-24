//! 历史旧文本智能导入（T2.6）：把非结构化文本解析为候选账号。
//!
//! 支持常见的手写/记事本格式：
//! - 标签式多行：`淘宝` / `账号：zhangsan` / `密码：123456` / `备注：…`
//! - 单行内联：`淘宝 账号：zhangsan 密码：123456`
//! - 括号平台名：`[淘宝]` 或 `【淘宝】`
//! - 无标签三行启发式：平台 / 账号 / 密码
//! - 多段以空行或 `---`/`===`/`***` 分隔

use serde::{Deserialize, Serialize};

use crate::error::VaultError;
use crate::models::{AccountInput, Importance};
use crate::Vault;

/// 解析出的候选账号（字段可空，附解析告警，供人工确认）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportCandidate {
    /// 应用/网站名。
    pub app_name: Option<String>,
    /// 账号/用户名。
    pub username: Option<String>,
    /// 登录密码。
    pub login_password: Option<String>,
    /// 网址。
    pub url: Option<String>,
    /// 备注。
    pub notes: Option<String>,
    /// 解析告警（如缺少平台名或密码）。
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    App,
    Username,
    Password,
    Url,
    Notes,
}

const fn labels(field: Field) -> &'static [&'static str] {
    match field {
        Field::App => &["平台名称", "应用名称", "网站名称", "平台", "应用", "名称", "app", "site"],
        Field::Username => &["用户名", "登陆账号", "登录账号", "账号", "帐号", "username", "user", "account", "login"],
        Field::Password => &["登录密码", "登陆密码", "密码", "password", "passwd", "pwd", "pass"],
        Field::Url => &["网址", "网站", "链接", "地址", "url", "link"],
        Field::Notes => &["备注说明", "备注", "说明", "note", "notes", "remark"],
    }
}

/// 按行拆分文本块（空行或纯分隔符行作为边界）。
fn split_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        let is_separator = !t.is_empty()
            && t.chars().all(|c| matches!(c, '-' | '=' | '*' | '#' | '~' | '_' | '+'));
        if t.is_empty() || is_separator {
            if !current.is_empty() {
                blocks.push(current.join("\n"));
                current.clear();
            }
        } else {
            current.push(t);
        }
    }
    if !current.is_empty() {
        blocks.push(current.join("\n"));
    }
    blocks
}

/// 仅对 ASCII 做小写转换，保持字节长度不变，便于安全切片。
fn ascii_lower(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_uppercase() { c.to_ascii_lowercase() } else { c })
        .collect()
}

/// 判断某标签出现处是否构成有效赋值（后接 `: ： =`，或后接空格再跟内容）。
fn valid_occurrence(line: &str, start: usize, label_len: usize) -> Option<usize> {
    let after = line.get(start + label_len..)?;
    let trimmed = after.trim_start_matches([' ', '\t']);
    let skipped = after.len() - trimmed.len();
    let mut chars = trimmed.chars();
    match chars.next() {
        None => None,
        Some(c) if matches!(c, ':' | '：' | '=') => Some(start + label_len + skipped + c.len_utf8()),
        Some(_) if skipped > 0 => Some(start + label_len + skipped),
        Some(_) => None,
    }
}

/// 在单行中提取所有「标签: 值」对，并返回未被标签覆盖的前缀文本。
fn extract_pairs(line: &str) -> (Vec<(Field, String)>, String) {
    let lowered = ascii_lower(line);
    let mut hits: Vec<(usize, usize, Field)> = Vec::new();
    let mut pos = 0;
    while pos < lowered.len() {
        let mut best: Option<(usize, usize, Field)> = None;
        for field in [Field::App, Field::Username, Field::Password, Field::Url, Field::Notes] {
            for label in labels(field) {
                let Some(rel) = lowered.get(pos..).and_then(|s| s.find(label)) else {
                    continue;
                };
                let at = pos + rel;
                let Some(value_start) = valid_occurrence(line, at, label.len()) else {
                    continue;
                };
                let better = match best {
                    None => true,
                    Some((b_at, _, _)) => at < b_at,
                };
                if better {
                    best = Some((at, value_start, field));
                }
            }
        }
        let Some((at, value_start, field)) = best else { break };
        hits.push((at, value_start, field));
        pos = value_start;
    }
    let mut pairs = Vec::new();
    for (i, (_at, value_start, field)) in hits.iter().enumerate() {
        let end = hits.get(i + 1).map_or(line.len(), |(next_at, _, _)| *next_at);
        let value = line
            .get(*value_start..end)
            .unwrap_or("")
            .trim()
            .trim_matches(|c| matches!(c, ',' | ';' | '，' | '；' | '、' | '-' | '—'))
            .trim();
        if !value.is_empty() {
            pairs.push((*field, value.to_owned()));
        }
    }
    let prefix_end = hits.first().map_or(line.len(), |(at, _, _)| *at);
    let prefix = line.get(..prefix_end).unwrap_or("").trim().to_owned();
    (pairs, prefix)
}

/// 提取 `[xxx]` / `【xxx】` 形式的平台名。
fn bracket_app(line: &str) -> Option<String> {
    for (open, close) in [('[', ']'), ('【', '】'), ('〖', '〗')] {
        if let Some(s) = line.find(open) {
            if let Some(e) = line.find(close) {
                if e > s + open.len_utf8() {
                    let inner = line.get(s + open.len_utf8()..e)?.trim();
                    if !inner.is_empty() {
                        return Some(inner.to_owned());
                    }
                }
            }
        }
    }
    None
}

fn parse_block(block: &str) -> ImportCandidate {
    let mut cand = ImportCandidate {
        app_name: None,
        username: None,
        login_password: None,
        url: None,
        notes: None,
        issues: Vec::new(),
    };
    let mut unlabeled: Vec<String> = Vec::new();

    for line in block.lines() {
        if let Some(app) = bracket_app(line) {
            if cand.app_name.is_none() {
                cand.app_name = Some(app);
            }
        }
        let (pairs, prefix) = extract_pairs(line);
        if !prefix.is_empty() {
            unlabeled.push(prefix);
        }
        for (field, value) in pairs {
            let slot = match field {
                Field::App => &mut cand.app_name,
                Field::Username => &mut cand.username,
                Field::Password => &mut cand.login_password,
                Field::Url => &mut cand.url,
                Field::Notes => &mut cand.notes,
            };
            if slot.is_none() {
                *slot = Some(value);
            }
        }
    }

    if cand.app_name.is_none() {
        if let Some(first) = unlabeled.first() {
            cand.app_name = Some(first.clone());
            unlabeled.remove(0);
        } else if let Some(host) = cand.url.as_deref().and_then(host_of) {
            cand.app_name = Some(host);
        }
    }

    if cand.login_password.is_none() && cand.username.is_none() && !unlabeled.is_empty() {
        cand.username = Some(unlabeled.remove(0));
        cand.issues.push("未识别到密码标签，已按顺序猜测账号".to_owned());
    }
    if cand.login_password.is_none() && !unlabeled.is_empty() {
        cand.login_password = Some(unlabeled.remove(0));
        cand.issues.push("未识别到密码标签，已按顺序猜测密码".to_owned());
    }

    if cand.app_name.is_none() {
        cand.issues.push("缺少平台/网站名".to_owned());
    }
    if cand.login_password.is_none() {
        cand.issues.push("缺少密码".to_owned());
    }
    cand
}

fn host_of(url: &str) -> Option<String> {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = without_scheme.split('/').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

/// 把整段文本解析为候选账号列表（空块被忽略）。
pub fn parse_notes(text: &str) -> Vec<ImportCandidate> {
    split_blocks(text)
        .into_iter()
        .map(|b| parse_block(&b))
        .filter(|c| {
            c.app_name.is_some() || c.username.is_some() || c.login_password.is_some()
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
        self.record_audit("import_candidates", None, None).ok();
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
        secondary_password: None,
        payment_password: None,
        api_key: None,
    };
    input.validate()?;
    Ok(input)
}
