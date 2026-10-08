/// FuxiPass 移动端入口（骨架）。
///
/// ⚠️ **未编译验证**：本骨架在无 Flutter SDK 的环境生成；请先按 `mobile/README.md`
/// 准备工具链与 `vault_ffi` 原生库，再 `flutter run`。
library;

import 'package:flutter/material.dart';

import 'screens/unlock_page.dart';

void main() => runApp(const FuxiPassApp());

class FuxiPassApp extends StatelessWidget {
  const FuxiPassApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '安全密码管家',
      theme: ThemeData(colorSchemeSeed: const Color(0xFF4F8CFF)),
      home: const UnlockPage(),
    );
  }
}
