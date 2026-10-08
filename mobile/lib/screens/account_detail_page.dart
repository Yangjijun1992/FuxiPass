/// 账号详情页（骨架）：高敏感字段需二次验证后揭示。
library;

import 'package:flutter/material.dart';

import '../vault_backend.dart';

/// 账号详情页：高敏感字段需二次验证后揭示。
class AccountDetailPage extends StatelessWidget {
  const AccountDetailPage({
    super.key,
    required this.backend,
    required this.account,
  });

  final VaultBackend backend;
  final AccountSummary account;

  Future<void> _reveal(BuildContext context, String fieldType) async {
    final controller = TextEditingController();
    final password = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('二次验证'),
        content: TextField(
          controller: controller,
          obscureText: true,
          decoration: const InputDecoration(labelText: '请输入主密码'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, controller.text),
            child: const Text('验证'),
          ),
        ],
      ),
    );
    if (password == null || !context.mounted) return;
    try {
      final value = await backend.revealSecret(
        accountId: account.id,
        fieldType: fieldType,
        masterPassword: password,
      );
      if (!context.mounted) return;
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: Text(fieldType),
          content: SelectableText(value),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('关闭'),
            ),
          ],
        ),
      );
    } on VaultException catch (e) {
      if (!context.mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('验证失败：${e.message}')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(account.appName)),
      body: ListView(
        children: [
          ListTile(
            title: const Text('账号'),
            subtitle: Text(account.username ?? '—'),
          ),
          ListTile(
            title: const Text('网址'),
            subtitle: Text(account.url ?? '—'),
          ),
          const Divider(),
          for (final field in account.fieldTypes)
            ListTile(
              title: Text(field),
              subtitle: const Text('••••••（需二次验证）'),
              trailing: TextButton(
                onPressed: () => _reveal(context, field),
                child: const Text('解锁查看'),
              ),
            ),
        ],
      ),
    );
  }
}
