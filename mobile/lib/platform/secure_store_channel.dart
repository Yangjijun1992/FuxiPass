/// 平台安全存储桥接（T1.4）。
///
/// Dart 侧通过 `MethodChannel` 调用原生实现（Android Keystore / iOS Keychain），
/// 方法与 Rust 的 `vault_store::secure_store::SecureStore` 一一对应。
///
/// ⚠️ **未编译验证**：本文件在无 Flutter SDK 的环境生成。
/// 原生实现契约见 `docs/07-移动端集成设计.md` §9.3 / §9.4。
library;

import 'dart:typed_data';

import 'package:flutter/services.dart';

/// AccountKey 条目标识（须与 Rust 侧 `ACCOUNT_KEY_ID` 一致）。
const String accountKeyId = 'fuxipass.account_key';

/// 平台安全存储通道。
class SecureStoreChannel {
  SecureStoreChannel({MethodChannel? channel})
      : _channel = channel ?? const MethodChannel('fuxipass/secure_store');

  final MethodChannel _channel;

  /// 写入密钥材料（原生侧应绑定用户认证）。
  Future<void> store(String id, Uint8List secret) =>
      _channel.invokeMethod<void>('store', {'id': id, 'secret': secret});

  /// 读取密钥材料；不存在返回 `null`。
  Future<Uint8List?> load(String id) async {
    final result = await _channel.invokeMethod<Uint8List>('load', {'id': id});
    return result;
  }

  /// 删除密钥材料。
  Future<void> delete(String id) => _channel.invokeMethod<void>('delete', {'id': id});

  /// 原生侧是否具备可用的生物识别（且已录入）。
  Future<bool> isBiometricAvailable() async =>
      await _channel.invokeMethod<bool>('isBiometricAvailable') ?? false;

  /// 触发一次生物识别认证（失败应返回 `false`，由上层回退主密码）。
  Future<bool> authenticate(String reason) async =>
      await _channel.invokeMethod<bool>('authenticate', {'reason': reason}) ?? false;
}
