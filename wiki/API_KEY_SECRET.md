# API Key Secret 静态保护

本文说明 Epusdt 如何保护 `api_keys.secret_key`，以及存量迁移、备份恢复、主密钥轮换和回滚步骤。

文中只有占位符。不要把真实 Secret、主密钥、钱包私钥、Token 或数据库原文写入仓库、镜像、日志或工单。

## 存储契约

- SQLite 的 `secret_key` 只保存版本化 AES-256-GCM envelope，不再保存可直接用于 HMAC 的明文。
- envelope JSON 字段：`format`、`version`、`key_id`、`nonce`、`ciphertext`。
- `format` 必须是 `epusdt.api-key-secret`，`version` 必须是 `1`。
- 每次写入使用 CSPRNG 生成独立 12 字节 nonce。
- AAD 绑定 API Key 行 ID、PID、格式版本和 `key_id`：

```text
epusdt/api-key-secret/v1|api_key_id=<id>|pid=<pid>|key=<key-id>
```

把一条密文复制到另一行或另一个 PID 会认证失败。

- 主密钥 keyring 只存在于数据库和镜像之外的配置文件（通常是 `.env`）。
- 单个主密钥是稳定的 32 字节值，编码为 64 位十六进制。应用启动时不会自动生成临时主密钥。

## 配置

```text
api_key_secret_active_key_id=master-v1
api_key_secret_active_key=<64-hex>
# 重叠轮换时的可读旧密钥：id=hex,id=hex
api_key_secret_decrypt_keys=
```

生成示例（在受控主机上执行，不要把输出提交到仓库）：

```sh
openssl rand -hex 32
```

首次安装向导会把一对新的 `master-v1` 写入 `.env`。已有 `.env` 若缺任一字段，HTTP 服务 fail closed，不会静默生成。

## 运行时

- 创建、轮换 API Key 只写入新 envelope。
- 建单验签、Webhook 签名、商户查单只在内部 HMAC 路径短暂解密。
- 密钥缺失、密文损坏、格式/版本未知、未知 `key_id`、AAD 失败时禁止对应支付操作。
- 正常运行路径拒绝读取明文。存量明文只能由显式 CLI 迁移。

## CLI

在应用配置和 SQLite 可访问的目录执行：

```sh
./epusdt --config /path/to/.env api-key-secret scan
./epusdt --config /path/to/.env api-key-secret migrate
./epusdt --config /path/to/.env api-key-secret reencrypt
```

输出只有计数、`key_id` 汇总和 `{id,class}` 失败清单，不会打印 Secret、密文或摘要。

## 存量迁移

1. 对 Epusdt SQLite 和 `.env` 做可读备份，并在隔离环境确认备份可恢复。备份仍是敏感制品。
2. `scan` 盘点 `total/envelope/plaintext/corrupt`。
3. `migrate` 逐条读取明文、用 active key 加密、回读比对。单条失败会停止。
4. 再次 `scan`，确认 `plaintext=0` 且 `decrypt_err=0`。
5. 从迁移后的备份恢复到隔离环境，用同一 keyring 验证建单、Webhook 验签和签名查单。
6. 只有 PENDING 订单、迟到付款观察窗口和旧 Secret 引用都排空后，才能删除旧商户 Key/PID 或旧主密钥。

同 PID 的管理端 `rotate-secret` 仍会覆盖商户 Secret，不能替代重叠 PID 轮换。

## 主密钥重叠轮换

1. 把新 32 字节密钥加入 `api_key_secret_decrypt_keys`。
2. 将 `api_key_secret_active_key_id` / `api_key_secret_active_key` 切到新密钥。
3. 重启后旧 envelope 仍可解密，新写入使用 active key。
4. `reencrypt` 把全部 envelope 重写为 active key。
5. `scan` 确认旧 `key_id` 计数为 0，并完成备份恢复验证。
6. 然后才允许从 `decrypt_keys` 删除旧主密钥。

## 回滚

- 回滚到本改动之前的二进制时，必须同时恢复迁移前的 SQLite 备份。旧进程会把 envelope 当成 HMAC 密钥，签名全部失败。
- 回滚后继续使用同一 keyring 文件；丢失主密钥即永久无法解密。
- 不要用文件权限 `0600`/`0700` 代替静态加密。
- 不要在回滚或排空完成前删除仍被密文引用的旧主密钥。

## 扫描证据要求

允许保留：行数、格式计数、布尔结果、错误类别。

禁止保留：Secret、密文全文、nonce、可离线猜测的摘要、真实 PID 以外的诊断原文。
