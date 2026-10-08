/// 保险库后端抽象接口。
///
/// 之所以抽象：便于「PC 端 HTTP 后端 / 移动端 FFI 后端」互换，
/// 也让 UI 代码不依赖任何具体传输方式（利于单元测试与后续替换）。
library;

/// 账号摘要（对应 Rust `vault_store::AccountSummary`）。
class AccountSummary {
  const AccountSummary({
    required this.id,
    required this.appName,
    this.url,
    this.username,
    required this.fieldTypes,
  });

  final String id;
  final String appName;
  final String? url;
  final String? username;
  final List<String> fieldTypes;
}

/// 保险库后端接口。
abstract class VaultBackend {
  /// 用主密码解锁；失败抛 [VaultException]。
  Future<void> unlock(String masterPassword);

  /// 锁定并释放内存中的密钥。
  Future<void> lock();

  /// 当前是否已解锁。
  bool get isUnlocked;

  /// 列出账号（可选关键词过滤）。
  Future<List<AccountSummary>> listAccounts({String? query});

  /// 揭示高敏感字段（需二次验证主密码）。
  Future<String> revealSecret({
    required String accountId,
    required String fieldType,
    required String masterPassword,
  });
}

/// 后端错误。
class VaultException implements Exception {
  const VaultException(this.code, this.message);

  final String code;
  final String message;

  @override
  String toString() => 'VaultException($code): $message';
}
