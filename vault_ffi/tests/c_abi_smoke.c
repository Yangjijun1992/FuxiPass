/*
 * vault_ffi C ABI 冒烟测试（等价于 Dart FFI 的调用路径）。
 *
 * 目的：从**外部调用方**（C）验证 .so 的 ABI 契约：
 *   1. 符号可解析、签名匹配（参数/返回值布局正确）
 *   2. 指针所有权契约正确（Rust 分配 → 调用方 free）
 *   3. 错误路径返回 NULL 且 last_error 可读
 *   4. 二次验证门控生效（未验证时揭示失败）
 *
 * 编译：cc smoke.c -L<dir> -lvault_ffi -lpthread -ldl -lm -o smoke
 * 运行：LD_LIBRARY_PATH=<dir> ./smoke <db路径> <主密码>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 与 vault_ffi/src/lib.rs 的 extern "C" 声明一一对应 */
extern void *fuxipass_unlock(const char *db_path, const char *master_password);
extern void fuxipass_lock(void *handle);
extern char *fuxipass_list_accounts(void *handle);
extern char *fuxipass_get_account(void *handle, const char *account_id);
extern int fuxipass_create_account(void *handle, const char *input_json);
extern int fuxipass_delete_account(void *handle, const char *account_id);
extern char *fuxipass_reveal_secret(void *handle, const char *account_id,
                                    const char *field_type,
                                    const char *master_password);
extern int fuxipass_unlock_second_factor(void *handle,
                                         const char *master_password);
extern char *fuxipass_lock_status(const char *db_path);
extern void fuxipass_string_free(char *value);
extern char *fuxipass_last_error(void);

static int failures = 0;

static void check(int condition, const char *what) {
    printf("  [%s] %s\n", condition ? "PASS" : "FAIL", what);
    if (!condition) {
        failures++;
    }
}

/* 取回并释放：验证「Rust 分配 → C 释放」的所有权契约 */
static char *take(char *p) {
    if (p == NULL) {
        return NULL;
    }
    char *copy = strdup(p);
    fuxipass_string_free(p);
    return copy;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "用法: %s <db路径> <主密码>\n", argv[0]);
        return 2;
    }
    const char *db = argv[1];
    const char *pw = argv[2];

    printf("== 1) 空指针入参应安全失败 ==\n");
    check(fuxipass_unlock(NULL, pw) == NULL, "unlock(NULL, pw) 返回 NULL");
    check(fuxipass_list_accounts(NULL) == NULL, "list(NULL) 返回 NULL");
    take(fuxipass_last_error());

    printf("== 2) 错误主密码应失败 ==\n");
    check(fuxipass_unlock(db, "definitely-wrong") == NULL,
          "unlock(错误密码) 返回 NULL");
    take(fuxipass_last_error());

    printf("== 3) 正确主密码解锁 ==\n");
    void *h = fuxipass_unlock(db, pw);
    check(h != NULL, "unlock 返回有效句柄");
    if (h == NULL) {
        char *e = take(fuxipass_last_error());
        fprintf(stderr, "  错误详情: %s\n", e ? e : "(null)");
        free(e);
        return 1;
    }

    printf("== 4) 列表（JSON 字符串所有权） ==\n");
    char *listed = take(fuxipass_list_accounts(h));
    check(listed != NULL, "list 返回非空 JSON");
    check(listed != NULL && strstr(listed, "测试站点") != NULL,
          "列表含预期条目");

    printf("== 5) 二次验证门控（FDEK） ==\n");
    /* 未二次验证时，读取高敏感字段必须失败 */
    char *id = NULL;
    if (listed != NULL) {
        /* 从 JSON 粗取 id（仅用于冒烟测试，不做完整解析） */
        const char *key = "\"id\":\"";
        const char *at = strstr(listed, key);
        if (at != NULL) {
            at += strlen(key);
            const char *end = strchr(at, '"');
            if (end != NULL) {
                size_t n = (size_t)(end - at);
                id = malloc(n + 1);
                memcpy(id, at, n);
                id[n] = '\0';
            }
        }
    }
    check(id != NULL, "解析出账号 id");
    if (id != NULL) {
        /* reveal 自带二次验证：错误主密码必须被拒 */
        char *denied =
            take(fuxipass_reveal_secret(h, id, "secondary_password", "wrong-pw"));
        check(denied == NULL, "二次验证失败时揭示被拒（返回 NULL）");
        take(fuxipass_last_error());

        printf("== 6) 二次验证后可揭示 ==\n");
        int code = fuxipass_unlock_second_factor(h, pw);
        check(code == 0, "unlock_second_factor 返回 0");
        char *revealed = take(fuxipass_reveal_secret(h, id, "secondary_password", pw));
        check(revealed != NULL && strstr(revealed, "888444") != NULL,
              "揭示得到正确值");
    }

    printf("== 7) 锁定状态查询（无需句柄） ==\n");
    char *status = take(fuxipass_lock_status(db));
    check(status != NULL && strstr(status, "locked") != NULL,
          "lock_status 返回 JSON");

    printf("== 8) 释放句柄与内存 ==\n");
    fuxipass_lock(h);
    check(1, "lock(handle) 未崩溃（句柄已释放）");

    free(listed);
    free(id);
    free(status);
    printf("\n%s（失败 %d 项）\n", failures == 0 ? "全部通过" : "存在失败", failures);
    return failures == 0 ? 0 : 1;
}
