//! 历史旧文本的解析算法（T2.6）。
//!
//! 支持格式见 `crate::import` 模块文档；本文件只负责「文本 → 候选」。

/// 可识别的字段类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field {
    App,
    Username,
    Password,
    SecondaryPassword,
    PaymentPassword,
    ApiKey,
    Url,
    Notes,
}

/// 各字段的可识别标签（中英文别名）。
pub(crate) const fn labels(field: Field) -> &'static [&'static str] {
    match field {
        Field::App => &["平台名称", "应用名称", "网站名称", "平台", "应用", "名称", "app", "site"],
        Field::Username => &[
            "用户名", "登陆账号", "登录账号", "账号", "帐号", "username", "user", "account", "login",
        ],
        Field::Password => &["登录密码", "登陆密码", "密码", "password", "passwd", "pwd", "pass"],
        Field::SecondaryPassword => &["二级密码", "安全码", "独立安全码"],
        Field::PaymentPassword => &["支付密码", "交易密码", "取款密码", "银行卡密码"],
        Field::ApiKey => &[
            "密钥", "私钥", "令牌", "api key", "api_key", "apikey", "access key", "secret", "token",
        ],
        Field::Url => &["网址", "网站", "链接", "地址", "url", "link"],
        Field::Notes => &["备注说明", "备注", "说明", "note", "notes", "remark"],
    }
}

/// 需要扫描的字段顺序（更具体者优先，便于同位置冲突时取更精确字段）。
const SCAN_ORDER: [Field; 8] = [
    Field::App,
    Field::PaymentPassword,
    Field::SecondaryPassword,
    Field::ApiKey,
    Field::Username,
    Field::Password,
    Field::Url,
    Field::Notes,
];

/// 按行拆分文本块（空行、纯分隔符行、`#` 注释行作为边界）。
pub(crate) fn split_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        let is_separator = !t.is_empty()
            && t.chars().all(|c| matches!(c, '-' | '=' | '*' | '#' | '~' | '_' | '+'));
        let is_comment = t.starts_with('#');
        if t.is_empty() || is_separator || is_comment {
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

/// 判断标签出现处是否构成有效赋值（后接 `: ： =`，或后接空格再跟内容）。
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
pub(crate) fn extract_pairs(line: &str) -> (Vec<(Field, String)>, String) {
    let lowered = ascii_lower(line);
    let mut hits: Vec<(usize, usize, Field)> = Vec::new();
    let mut pos = 0;
    while pos < lowered.len() {
        let mut best: Option<(usize, usize, Field)> = None;
        for field in SCAN_ORDER {
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

/// 提取 `[xxx]` / `【xxx】` / `〖xxx〗` 形式的平台名。
pub(crate) fn bracket_app(line: &str) -> Option<String> {
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
