/// 账号列表页（骨架）。
library;

import 'package:flutter/material.dart';

import '../vault_backend.dart';
import 'account_detail_page.dart';

/// 账号列表页：检索 + 详情。
class AccountListPage extends StatefulWidget {
  const AccountListPage({super.key, required this.backend});

  final VaultBackend backend;

  @override
  State<AccountListPage> createState() => _AccountListPageState();
}

class _AccountListPageState extends State<AccountListPage> {
  List<AccountSummary> _items = const [];
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load({String? query}) async {
    try {
      final items = await widget.backend.listAccounts(query: query);
      if (!mounted) return;
      setState(() => _items = items);
    } on VaultException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('账号'),
        actions: [
          IconButton(
            icon: const Icon(Icons.lock_outline),
            tooltip: '锁定',
            onPressed: () async {
              await widget.backend.lock();
              if (!context.mounted) return;
              Navigator.of(context).pop();
            },
          ),
        ],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(12),
            child: TextField(
              decoration: const InputDecoration(
                hintText: '搜索：平台名 / 网址 / 账号',
                prefixIcon: Icon(Icons.search),
              ),
              onChanged: (v) => _load(query: v.isEmpty ? null : v),
            ),
          ),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: Text(_error!, style: const TextStyle(color: Colors.red)),
            ),
          Expanded(
            child: ListView.builder(
              itemCount: _items.length,
              itemBuilder: (context, i) {
                final a = _items[i];
                return ListTile(
                  title: Text(a.appName),
                  subtitle: Text('${a.username ?? '—'} · ${a.url ?? '—'}'),
                  trailing: Text('${a.fieldTypes.length} 个字段'),
                  onTap: () => Navigator.of(context).push(
                    MaterialPageRoute(
                      builder: (_) => AccountDetailPage(
                        backend: widget.backend,
                        account: a,
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}
