/// 解锁页（骨架）。
library;

import 'package:flutter/material.dart';

import '../vault_backend.dart';
import 'account_list_page.dart';

/// 解锁页：输入主密码 → 进入列表页。
///
/// `backend` 由外部注入（移动端注入 FFI 实现，测试可注入假实现）。
class UnlockPage extends StatefulWidget {
  const UnlockPage({super.key, this.backend});

  final VaultBackend? backend;

  @override
  State<UnlockPage> createState() => _UnlockPageState();
}

class _UnlockPageState extends State<UnlockPage> {
  final _controller = TextEditingController();
  String? _error;
  bool _busy = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final backend = widget.backend;
    if (backend == null) {
      setState(() => _error = '未注入后端实现（需先实现 vault_ffi 并接入）');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await backend.unlock(_controller.text);
      _controller.clear();
      if (!mounted) return;
      await Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => AccountListPage(backend: backend)),
      );
    } on VaultException catch (e) {
      setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('解锁保险库')),
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            TextField(
              controller: _controller,
              obscureText: true,
              decoration: const InputDecoration(labelText: '主密码'),
              onSubmitted: (_) => _submit(),
            ),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(top: 12),
                child: Text(_error!, style: const TextStyle(color: Colors.red)),
              ),
            const SizedBox(height: 20),
            FilledButton(
              onPressed: _busy ? null : _submit,
              child: Text(_busy ? '解锁中…' : '解锁'),
            ),
          ],
        ),
      ),
    );
  }
}
