/// `vault_ffi` 的 dart:ffi 绑定（对应 `docs/07-移动端集成设计.md` §3 契约）。
///
/// ⚠️ **未编译验证**：本工程骨架在无 Flutter SDK 的环境下生成，
/// 需在有工具链的机器上 `flutter pub get` 后修正（如 API 变更）。
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import '../vault_backend.dart';

/// 不透明句柄（对应 Rust 侧 `*mut FuxiHandle`）。
final class FuxiHandle extends Opaque {}

typedef _UnlockC = Pointer<FuxiHandle> Function(
  Pointer<Utf8> dbPath,
  Pointer<Utf8> masterPassword,
);
typedef _UnlockDart = Pointer<FuxiHandle> Function(
  Pointer<Utf8> dbPath,
  Pointer<Utf8> masterPassword,
);

typedef _VoidHandleC = Void Function(Pointer<FuxiHandle> handle);
typedef _VoidHandleDart = void Function(Pointer<FuxiHandle> handle);

typedef _StringHandleC = Pointer<Utf8> Function(Pointer<FuxiHandle> handle);
typedef _StringHandleDart = Pointer<Utf8> Function(Pointer<FuxiHandle> handle);

typedef _RevealC = Pointer<Utf8> Function(
  Pointer<FuxiHandle> handle,
  Pointer<Utf8> accountId,
  Pointer<Utf8> fieldType,
  Pointer<Utf8> masterPassword,
);
typedef _RevealDart = Pointer<Utf8> Function(
  Pointer<FuxiHandle> handle,
  Pointer<Utf8> accountId,
  Pointer<Utf8> fieldType,
  Pointer<Utf8> masterPassword,
);

typedef _FreeStringC = Void Function(Pointer<Utf8> value);
typedef _FreeStringDart = void Function(Pointer<Utf8> value);

typedef _LockStatusC = Pointer<Utf8> Function(Pointer<Utf8> dbPath);
typedef _LockStatusDart = Pointer<Utf8> Function(Pointer<Utf8> dbPath);

/// 原生库名称（Android 为 `libvault_ffi.so`，iOS 为静态链接）。
const String _libName = 'vault_ffi';

DynamicLibrary _open() {
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('lib$_libName.so');
  }
  if (Platform.isIOS || Platform.isMacOS) {
    return DynamicLibrary.process();
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('$_libName.dll');
  }
  throw UnsupportedError('不支持的平台');
}

/// Rust FFI 的 Dart 封装。
class VaultFfi {
  VaultFfi() : _lib = _open();

  final DynamicLibrary _lib;

  Pointer<FuxiHandle> Function(Pointer<Utf8>, Pointer<Utf8>) get _unlock =>
      _lib.lookupFunction<_UnlockC, _UnlockDart>('fuxipass_unlock');

  void Function(Pointer<FuxiHandle>) get _lock =>
      _lib.lookupFunction<_VoidHandleC, _VoidHandleDart>('fuxipass_lock');

  Pointer<Utf8> Function(Pointer<FuxiHandle>) get _list =>
      _lib.lookupFunction<_StringHandleC, _StringHandleDart>(
        'fuxipass_list_accounts',
      );

  Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>)
      get _reveal =>
          _lib.lookupFunction<_RevealC, _RevealDart>('fuxipass_reveal_secret');

  Pointer<Utf8> Function(Pointer<Utf8>) get _lockStatus =>
      _lib.lookupFunction<_LockStatusC, _LockStatusDart>('fuxipass_lock_status');

  void Function(Pointer<Utf8>) get _freeString =>
      _lib.lookupFunction<_FreeStringC, _FreeStringDart>('fuxipass_string_free');

  /// 解锁；失败返回 `null`（错误详情见 `fuxipass_last_error`）。
  Pointer<FuxiHandle>? unlock(String dbPath, String masterPassword) {
    final pathPtr = dbPath.toNativeUtf8();
    final pwPtr = masterPassword.toNativeUtf8();
    try {
      final handle = _unlock(pathPtr, pwPtr);
      if (handle == nullptr) return null;
      return handle;
    } finally {
      calloc.free(pathPtr);
      calloc.free(pwPtr);
    }
  }

  /// 释放句柄（Rust 侧 Drop 会 zeroize 密钥）。
  void lock(Pointer<FuxiHandle> handle) => _lock(handle);

  /// 账号列表 JSON；调用方负责 `freeString`。
  String listAccounts(Pointer<FuxiHandle> handle) => _take(_list(handle));

  /// 揭示高敏感字段（需主密码二次验证）。
  String reveal(
    Pointer<FuxiHandle> handle,
    String accountId,
    String fieldType,
    String masterPassword,
  ) {
    final idPtr = accountId.toNativeUtf8();
    final fieldPtr = fieldType.toNativeUtf8();
    final pwPtr = masterPassword.toNativeUtf8();
    try {
      return _take(_reveal(handle, idPtr, fieldPtr, pwPtr));
    } finally {
      calloc.free(idPtr);
      calloc.free(fieldPtr);
      calloc.free(pwPtr);
    }
  }

  /// 锁定状态 JSON（无需解锁）。
  String lockStatus(String dbPath) {
    final pathPtr = dbPath.toNativeUtf8();
    try {
      return _take(_lockStatus(pathPtr));
    } finally {
      calloc.free(pathPtr);
    }
  }

  /// 读取 Rust 分配的字符串并释放，避免内存泄漏（对应 Category 12）。
  String _take(Pointer<Utf8> ptr) {
    if (ptr == nullptr) return '';
    try {
      return ptr.toDartString();
    } finally {
      _freeString(ptr);
    }
  }
}

/// 解析 FFI 返回 JSON 的辅助（供 FFI 后端实现使用）。
List<AccountSummary> parseAccountList(String json) {
  final list = jsonDecode(json) as List<dynamic>;
  return list
      .cast<Map<String, dynamic>>()
      .map(
        (m) => AccountSummary(
          id: m['id'] as String,
          appName: m['app_name'] as String,
          url: m['url'] as String?,
          username: m['username'] as String?,
          fieldTypes:
              (m['field_types'] as List<dynamic>).cast<String>(),
        ),
      )
      .toList();
}
