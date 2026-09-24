//! 智能导入解析器测试（T2.6）：覆盖常见旧文本格式与边界情况。

use vault_store::{parse_notes, ImportCandidate};

fn first(text: &str) -> ImportCandidate {
    let mut v = parse_notes(text);
    assert_eq!(v.len(), 1, "应解析出恰好 1 条候选");
    v.remove(0)
}

#[test]
fn parses_labeled_multiline_block() {
    let c = first("淘宝\n账号：zhangsan\n密码：Taobao#2024\n备注：常用购物");
    assert_eq!(c.app_name.as_deref(), Some("淘宝"));
    assert_eq!(c.username.as_deref(), Some("zhangsan"));
    assert_eq!(c.login_password.as_deref(), Some("Taobao#2024"));
    assert_eq!(c.notes.as_deref(), Some("常用购物"));
    assert!(c.issues.is_empty(), "issues={:?}", c.issues);
}

#[test]
fn parses_inline_single_line() {
    let c = first("建设银行 账号：123456789 密码：Ccb@2024");
    assert_eq!(c.app_name.as_deref(), Some("建设银行"));
    assert_eq!(c.username.as_deref(), Some("123456789"));
    assert_eq!(c.login_password.as_deref(), Some("Ccb@2024"));
}

#[test]
fn parses_bracket_app_name() {
    let c = first("【中国国家图书馆】\n用户名: reader\n密码: Nlc#2021");
    assert_eq!(c.app_name.as_deref(), Some("中国国家图书馆"));
    assert_eq!(c.username.as_deref(), Some("reader"));
    assert_eq!(c.login_password.as_deref(), Some("Nlc#2021"));
}

#[test]
fn parses_english_labels_with_equals() {
    let c = first("GitHub\nusername=dev\npassword=Gh!2024");
    assert_eq!(c.app_name.as_deref(), Some("GitHub"));
    assert_eq!(c.username.as_deref(), Some("dev"));
    assert_eq!(c.login_password.as_deref(), Some("Gh!2024"));
}

#[test]
fn splits_multiple_blocks_and_ignores_separators() {
    let text = "淘宝\n账号：a\n密码：p1\n\n---\n\n京东\n账号：b\n密码：p2\n\n===\n\n微信\n账号：c\n密码：p3";
    let all = parse_notes(text);
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].app_name.as_deref(), Some("淘宝"));
    assert_eq!(all[1].app_name.as_deref(), Some("京东"));
    assert_eq!(all[2].app_name.as_deref(), Some("微信"));
}

#[test]
fn flags_missing_password() {
    let c = first("某网站\n账号：onlyuser");
    assert_eq!(c.app_name.as_deref(), Some("某网站"));
    assert_eq!(c.username.as_deref(), Some("onlyuser"));
    assert!(c.login_password.is_none());
    assert!(c.issues.iter().any(|i| i.contains("缺少密码")));
}

#[test]
fn heuristics_three_unlabeled_lines() {
    let c = first("网易邮箱\nmailuser\nMail#2024");
    assert_eq!(c.app_name.as_deref(), Some("网易邮箱"));
    assert_eq!(c.username.as_deref(), Some("mailuser"));
    assert_eq!(c.login_password.as_deref(), Some("Mail#2024"));
    assert!(!c.issues.is_empty(), "按顺序猜测时应给出告警");
}

#[test]
fn derives_app_from_url_host_when_missing() {
    let c = first("网址：https://mail.163.com/login\n账号：u1\n密码：p1");
    assert_eq!(c.app_name.as_deref(), Some("mail.163.com"));
}

#[test]
fn does_not_mistake_words_for_labels() {
    let c = first("我的账号备忘\n账号：realuser\n密码：RealPw123");
    assert_eq!(c.app_name.as_deref(), Some("我的账号备忘"));
    assert_eq!(c.username.as_deref(), Some("realuser"));
}

#[test]
fn empty_and_noise_text_yields_nothing() {
    assert!(parse_notes("").is_empty());
    assert!(parse_notes("----\n\n===\n").is_empty());
}

#[test]
fn ignores_comment_lines_starting_with_hash() {
    let text = "# 这是说明：不应被解析\n# 密码：假密码\n\n淘宝\n账号：u\n密码：p";
    let all = parse_notes(text);
    assert_eq!(all.len(), 1, "注释行不应产生候选");
    assert_eq!(all[0].app_name.as_deref(), Some("淘宝"));
    assert_eq!(all[0].login_password.as_deref(), Some("p"));
}

#[test]
fn distinguishes_payment_secondary_and_api_key_fields() {
    let c = first("中国银行\n账号：622425199202012358\n登录密码：LoginPw1\n二级密码：SecPw2\n支付密码：PayPw3\n密钥：sk-abc123");
    assert_eq!(c.username.as_deref(), Some("622425199202012358"));
    assert_eq!(c.login_password.as_deref(), Some("LoginPw1"));
    assert_eq!(c.secondary_password.as_deref(), Some("SecPw2"));
    assert_eq!(c.payment_password.as_deref(), Some("PayPw3"));
    assert_eq!(c.api_key.as_deref(), Some("sk-abc123"));
    assert!(c.issues.is_empty(), "issues={:?}", c.issues);
}

#[test]
fn bank_card_password_maps_to_payment_slot() {
    let c = first("杭州银行\n银行卡密码：012358");
    assert_eq!(c.payment_password.as_deref(), Some("012358"));
    assert!(c.login_password.is_none());
}

#[test]
fn bracket_app_line_is_not_treated_as_username() {
    let c = first("[DeepSeek API]\n密钥：sk-test");
    assert_eq!(c.app_name.as_deref(), Some("DeepSeek API"));
    assert!(c.username.is_none(), "括号行不应被当作账号");
    assert_eq!(c.api_key.as_deref(), Some("sk-test"));
}

#[test]
fn notes_only_entry_is_kept_with_missing_password_issue() {
    let c = first("[待补录站点]\n备注：账号密码待补充");
    assert_eq!(c.app_name.as_deref(), Some("待补录站点"));
    assert!(c.issues.iter().any(|i| i.contains("缺少密码")));
    assert!(c.issues.iter().any(|i| i.contains("缺少平台") == false));
}
