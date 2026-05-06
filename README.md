# springboot4-jdk21-demo

Spring Boot 4.0.5 + JDK 21 防程序请求演示项目（Gydev 工具化封装版）。

## 1. 项目启动

```bash
mvn spring-boot:run
```

默认端口：`8080`

## 1.1 GitHub Tag 触发 GHCR 镜像发布

本项目已提供 GitHub Actions 工作流：`.github/workflows/release-ghcr.yml`。  
当你 push `v*` 格式 tag（如 `v1.0.0`）时，会自动构建并推送镜像到 GHCR：

- 镜像地址：`ghcr.io/<你的组织或用户名>/<仓库名>`
- 标签：
  - `v1.0.0`（对应 tag）
  - `latest`

### 使用步骤

1. 将仓库推送到 GitHub（默认分支）。
2. 确保仓库 Actions 已启用（默认开启）。
3. 本地打 tag 并推送：

```bash
git tag -a v1.0.0 -m "release v1.0.0"
git push origin v1.0.0
```

4. 在 GitHub `Actions` 页面查看 `Release GHCR Image` 流水线。

### 拉取与运行镜像

```bash
docker pull ghcr.io/<owner>/<repo>:v1.0.0
docker run --rm -p 8080:8080 ghcr.io/<owner>/<repo>:v1.0.0
```

## 2. 工具类能力总览

本项目将接口防护能力统一封装为一套 `Gydev` 工具层，可在初始化时选择启用：

1. TLS 指纹识别
2. H2 指纹识别
3. `gydev_token`（类 arkose token）
4. `Gydev-Sentinel-Proof-Token`（类 Sentinel PoW token）

关闭某能力后，系统采用“跳过校验”策略：不阻断请求，并在结果里标记 `enabled=false`、`skipped=true`。

## 3. 后端封装使用说明

### 3.1 核心类

- 配置类：`com.example.demo.service.gydev.GydevGuardConfig`
- 统一编排：`com.example.demo.service.gydev.GydevGuardService`
- 模块适配：
  - `TlsFingerprintGuard`
  - `GydevTokenGuard`
  - `SentinelProofGuard`

### 3.2 初始化开关（Spring Bean）

在 `GydevGuardConfiguration` 中配置：

```java
config.setEnableTlsFingerprint(true);
config.setEnableH2Fingerprint(true);
config.setEnableGydevToken(true);
config.setEnableSentinelProofToken(true);
```

### 3.3 HTTP 演示接口

- `GET /api/gydev/challenge/init`
  - 返回：`challengeId`、`expiresAt`、`salt`、`publicParams`、`pow`、`guardConfig`
- `GET /api/gydev/submit-get`
  - Query 参数：
    - `content`
  - Header 参数（仅新命名）：
    - `gydev_token`
    - `Gydev-Sentinel-Proof-Token`
- `POST /api/gydev/submit-post`
  - Body（JSON）字段：
    - `content`
  - Header 参数（仅新命名）：
    - `gydev_token`
    - `Gydev-Sentinel-Proof-Token`

> 注意：旧字段 `riskToken/proofToken` 已不兼容。

## 4. 前端封装使用说明（TypeScript SDK）

SDK 文件：

- TypeScript：`/gydev-guard-sdk.ts`
- 浏览器可直接引入：`/gydev-guard-sdk.js`

### 4.1 初始化

```javascript
const sdk = new window.GydevGuardSdk();
sdk.init({
  features: {
    tlsFingerprint: true,
    h2Fingerprint: true,
    gydevToken: true,
    sentinelProofToken: true
  }
});
```

### 4.2 API

- `initChallenge()`
- `createGydevToken()`
- `createSentinelProofToken(gydevToken)`
- `submitGet(content, gydevToken, sentinelToken)`
- `submitPost(content, gydevToken, sentinelToken)`

## 5. DEMO 页面

页面地址：

`http://localhost:8080/risk-demo.html`

支持：

- GET 提交
- POST 提交

流程：

1. 点击“生成 Token”
2. 自动生成 `gydev_token`
3. 自动计算 `Gydev-Sentinel-Proof-Token`（Web Worker）
4. 选择 GET/POST 并提交

## 6. 请求字段规范（统一新命名）

- `content`
- `gydev_token`
- `Gydev-Sentinel-Proof-Token`

## 7. PoW 规则（演示默认）

- 算法：`sha256-prefix-zero`
- 难度：`4`
- 时效：`60s`
- 规则：
  - `sha256(challengeId|riskNonce|proofNonce|ts)` 前缀满足 `0000`

## 8. 测试

```bash
mvn test
```

已包含：

- Gydev 封装层开关分支测试
- GET/POST 控制器测试
- Token 与 PoW 通过/失败分支测试

## 9. Nginx 透传示例（TLS/H2）

如需在 `/api/tls` 或 Gydev 模块中使用上游指纹，可在网关透传：

```nginx
proxy_set_header X-JA3 $http_x_ja3;
proxy_set_header X-JA4 $http_x_ja4;
proxy_set_header X-H2-FP $http_x_h2_fp;
proxy_set_header X-H2-SETTINGS $http_x_h2_settings;
proxy_set_header X-H2-WINDOW $http_x_h2_window;
proxy_set_header X-H2-PRIORITY $http_x_h2_priority;
```

## 10. 生产建议

1. `gydev_token` 与 `Gydev-Sentinel-Proof-Token` 建议统一走 Header（本项目已默认如此），避免 URL 暴露与超长问题。
2. 防重放从内存迁移到 Redis（分布式部署必做）。
3. 根据风险分动态调整 PoW 难度。
4. 为 Gydev 开关增加配置中心热更新能力（灰度发布）。
