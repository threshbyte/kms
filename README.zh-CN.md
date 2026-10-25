# KMSLab

[English](README.md) | **简体中文**

自托管的密钥管理服务，面向需要加密敏感数据库字段、并且自己掌握密钥的团队。

业界常见的 "KMS SDK" 大多是密钥**分发**服务：把明文数据密钥交给应用，由应用自己加密。这等于把信任边界放在应用进程，而不是密钥库——一次堆转储或一个调试端口就能拿走全部密钥，一个泄露的令牌可以解开整个数据库。KMSLab 的立场相反：密钥留在服务内部，密文自描述，每一次密钥使用都记入一条任何人都能验证的链。


## 它做什么

- **带认证的字段级加密。** 值用 AES-256-GCM 封装在带版本的 envelope 中。加密上下文（租户、表、列、主键）绑定进 AAD，因此从一行复制到另一行的密文会解密失败，而不是悄悄泄露别人的数据。
- **可运维的密钥生命周期。** 创建、轮转、禁用、计划删除、取消、销毁。轮转增加的是版本而不是换一把新密钥，旧密文照常可解，不需要字段映射表。
- **职责分离的授权。** 写入服务可以只拿到 `ENCRYPT`：它能写密文，却永远读不回来。密钥管理与数据访问是两份不同的授权。
- **只能收窄的能力令牌。** 短时、签名、可由持有者衰减。上游可以把一个严格更弱的令牌交给下游，不必回源签发方。
- **可验证的审计。** 每次密钥操作追加进哈希链；续接前先验证，再继续往下写。
- **持久状态。** 一个 append-only journal，确认前先 fsync，重启时重放。

## 如何工作

信封加密，三层：

```
KEK  (per tenant x purpose, versioned, wrapped under a storage root key)
 └── DEK  (32 random bytes per encryption)
      └── subkey = HKDF-SHA256(DEK, salt = SHA-256(canonical(ctx)))
```

密文自带解密所需的全部路由信息：

```
kms1.<base64url(header)>.<base64url(nonce || ciphertext || tag)>

header = ver | alg | key_id(16B) | key_ver(4B) | wrap | dek_wrap(40B) | ctx_hash(32B)
```

全部 95 字节 header 都在 AAD 之内。改动算法字节、密钥版本或上下文，都会导致解密失败，而不是降级。格式在 [docs/envelope-v1.md](docs/envelope-v1.md) 中逐字节规定，并附带一致性向量，因此其他语言的实现可以互通。

## 模块

| 模块 | 职责 |
|---|---|
| `kmslab-envelope` | `kms1` 格式：AEAD、密钥派生、DEK 封装。零运行时依赖，可以一次读完再判断。 |
| `kmslab-core` | 领域层：密钥生命周期、策略、审计链、能力令牌、加密编排。不依赖框架。 |
| `kmslab-server` | 基于 JDK 服务器与虚拟线程的 HTTP 接口。 |
| `kmslab-sdk-java` | 类型化客户端，对着真实服务器做集成测试。 |
| `kmslab-store` | append-only journal，以及让密钥材料在静态存储中保持封装的 KEK vault。 |

## 快速开始

需要 JDK 21。构建脚本会固定版本——很多机器上的系统 `java` 更旧，所以请用 wrapper 而不是直接 `mvn`。

```bash
./build.sh test      # 单元测试与集成测试
./verify.sh          # 测试 + 跨语言一致性校验
./build.sh package   # 打包
```

通过 SDK 加密一个字段：

```java
try (KmsClient kms = KmsClient.builder("https://kms.internal")
        .token(() -> identity.currentToken())
        .build()) {

    Key key = kms.createKey("user-phone", false);
    UUID keyId = UUID.fromString(key.keyId());

    Map<String, String> ctx = Map.of(
            "tenant", "pay", "table", "user", "column", "phone", "row_pk", "10086");

    String envelope = kms.encrypt(keyId, ctx, phoneBytes);
    byte[] plain   = kms.decrypt(ctx, envelope, Purpose.USER_VIEW);
}
```

同样的操作走 HTTP：

```bash
curl -sX POST https://kms.internal/v1/encrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"keyId":"...","ctx":{"tenant":"pay","table":"user","column":"phone","row_pk":"10086"},
       "plaintextBase64":"MTM4MDAxMzgwMDA="}'
```

## HTTP 接口

| 方法 | 路径 | 用途 |
|---|---|---|
| `GET` | `/v1/health` | 存活检查，免鉴权 |
| `POST` | `/v1/keys` | 创建密钥 |
| `POST` | `/v1/keys/{id}/rotate` `.../disable` `.../enable` | 生命周期 |
| `POST` | `/v1/keys/{id}/schedule-deletion` `.../cancel-deletion` `.../purge` | 破坏性操作，带闸门 |
| `POST` | `/v1/encrypt` | 封装一个值 |
| `POST` | `/v1/decrypt` | 解开一个值；必须带 purpose |
| `POST` | `/v1/datakeys` | 导出数据密钥（仅限为此创建的密钥） |

错误同时给出分类与具体原因：

```json
{"error": {"code": "INVALID_STATE", "reason": "KEY_STATE_DISABLED", "message": "denied: ..."}}
```

## 安全边界

诚实的边界——一个夸大的密钥服务比没有更糟：

- **密钥材料不出服务。** 只有显式创建为 `exportAllowed` 的密钥才能导出数据密钥，而最敏感的数据恰恰应当避开这种模式。
- **存储根密钥由你保护。** 静态存储时，KEK 材料封装在调用方提供的 32 字节根密钥之下。如果这把根密钥和 journal 在同一块磁盘上，你换来的是可用性，不是机密性。
- **内存态 KEK 只用于开发。** `SoftKeyWrapper` 服务于测试与本地运行。生产需要云 KMS 或 HSM 作为根，接口已经预留。
- **审计链能证明日志未被改动**，但不能证明服务从未把明文交给过有权限的调用方——那是窄授权与 purpose 字段要解决的问题。

## 文档

- [docs/envelope-v1.md](docs/envelope-v1.md) —— 密文格式，字节级
- [docs/conventions.md](docs/conventions.md) —— 序列化、依赖与命名策略

## 状态

单节点可用：信封格式、密钥生命周期、策略、审计链、能力令牌、HTTP 接口、Java SDK 与持久存储均已端到端打通。尚未完成：生产级根信任（云 KMS 或 PKCS#11）、多节点复制、以及用于透明字段加密的 JDBC/JPA 适配器。
