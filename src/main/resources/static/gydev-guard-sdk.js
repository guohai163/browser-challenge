/**
 * Gydev 前端防护 SDK。
 * <p>
 * 负责 challenge 初始化、Gydev-Token 生成、PoW 计算与 GET/POST 提交封装。
 */
class GydevGuardSdk {
    /**
     * 创建 SDK 实例并初始化默认配置与交互统计监听。
     */
    constructor() {
        this.firstInteractionAt = performance.now();
        this.interactionCount = 0;
        this.config = {
            baseUrl: "",
            endpoints: {
                initChallenge: "/api/gydev/challenge/init",
                submitGet: "/api/gydev/submit-get",
                submitPost: "/api/gydev/submit-post",
            },
            features: {
                tlsFingerprint: true,
                h2Fingerprint: true,
                gydevToken: true,
                sentinelProofToken: true,
            },
        };
        this.state = {
            challengeId: "",
            salt: "",
            expiresAtMs: 0,
            pow: { algo: "sha256-prefix-zero", difficulty: 4, maxAgeMs: 60000 },
        };
        this.powWorker = this.createPowWorker();
        document.addEventListener("mousemove", () => this.interactionCount++);
        document.addEventListener("keydown", () => this.interactionCount++);
        document.addEventListener("click", () => this.interactionCount++);
    }
    /**
     * 初始化 SDK 配置。
     *
     * @param config 外部传入配置
     */
    init(config) {
        this.config = {
            baseUrl: config.baseUrl ?? "",
            endpoints: {
                initChallenge: config.endpoints?.initChallenge ?? "/api/gydev/challenge/init",
                submitGet: config.endpoints?.submitGet ?? "/api/gydev/submit-get",
                submitPost: config.endpoints?.submitPost ?? "/api/gydev/submit-post",
            },
            features: {
                tlsFingerprint: config.features?.tlsFingerprint ?? true,
                h2Fingerprint: config.features?.h2Fingerprint ?? true,
                gydevToken: config.features?.gydevToken ?? true,
                sentinelProofToken: config.features?.sentinelProofToken ?? true,
            },
        };
    }
    /**
     * 初始化挑战参数并刷新本地状态。
     *
     * @returns challenge/init 响应载荷
     */
    async initChallenge() {
        const res = await fetch(this.withBase(this.config.endpoints.initChallenge));
        if (!res.ok)
            throw new Error("init challenge failed");
        const data = (await res.json());
        this.state.challengeId = data.challengeId;
        this.state.salt = data.salt;
        this.state.expiresAtMs = Date.parse(data.expiresAt);
        if (data.pow)
            this.state.pow = data.pow;
        return data;
    }
    /**
     * 生成 Gydev-Token。
     *
     * @returns Gydev-Token；若功能关闭则返回空字符串
     */
    async createGydevToken() {
        if (!this.config.features.gydevToken)
            return "";
        if (!this.state.challengeId || Date.now() > this.state.expiresAtMs) {
            await this.initChallenge();
        }
        const ua = navigator.userAgent || "";
        const lang = navigator.language || "";
        const secChUa = this.canonicalSecChUaFromNavigator();
        const headerPrefix = (await this.sha256Hex(`${ua}|${lang}|${secChUa}`)).slice(0, 12);
        const fpHash = `${headerPrefix}:${(await this.collectDeviceHash()).slice(0, 24)}`;
        const payload = {
            v: 1,
            ts: Date.now(),
            challengeId: this.state.challengeId,
            nonce: this.randomHex(8),
            fpHash,
            behScore: this.behaviorScore(),
        };
        const base = `${payload.v}|${payload.ts}|${payload.challengeId}|${payload.nonce}|${payload.fpHash}|${payload.behScore}`;
        payload.sig = await this.hmacSha256Hex(this.state.salt, base);
        return this.base64UrlEncode(JSON.stringify(payload));
    }
    /**
     * 生成 Gydev-Sentinel-Proof-Token（PoW）。
     *
     * @param gydevToken 已生成的 Gydev-Token
     * @returns Proof Token；若功能关闭则返回空字符串
     */
    async createSentinelProofToken(gydevToken) {
        if (!this.config.features.sentinelProofToken)
            return "";
        const parsed = JSON.parse(this.base64UrlDecode(gydevToken));
        return await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error("pow timeout")), 120000);
            this.powWorker.onmessage = (e) => {
                clearTimeout(timeout);
                resolve(this.base64UrlEncode(JSON.stringify(e.data)));
            };
            this.powWorker.onerror = (e) => {
                clearTimeout(timeout);
                reject(new Error("pow worker error: " + e.message));
            };
            this.powWorker.postMessage({
                challengeId: parsed.challengeId,
                riskNonce: parsed.nonce,
                difficulty: this.state.pow.difficulty || 4,
            });
        });
    }
    /**
     * 使用 GET 方式提交受保护请求。
     *
     * @param content 业务内容
     * @param gydevToken Gydev-Token
     * @param sentinelToken Gydev-Sentinel-Proof-Token
     * @returns 后端响应
     */
    async submitGet(content, gydevToken, sentinelToken) {
        const url = new URL(this.withBase(this.config.endpoints.submitGet), window.location.origin);
        url.searchParams.set("content", content);
        const res = await fetch(url.toString(), {
            headers: {
                "Gydev-Token": gydevToken,
                "Gydev-Sentinel-Proof-Token": sentinelToken,
            },
        });
        return await res.json();
    }
    /**
     * 使用 POST 方式提交受保护请求。
     *
     * @param content 业务内容
     * @param gydevToken Gydev-Token
     * @param sentinelToken Gydev-Sentinel-Proof-Token
     * @returns 后端响应
     */
    async submitPost(content, gydevToken, sentinelToken) {
        const payload = {
            content,
        };
        const res = await fetch(this.withBase(this.config.endpoints.submitPost), {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Gydev-Token": gydevToken,
                "Gydev-Sentinel-Proof-Token": sentinelToken,
            },
            body: JSON.stringify(payload),
        });
        return await res.json();
    }
    /**
     * 拼接基础地址与接口路径。
     */
    withBase(path) {
        return `${this.config.baseUrl}${path}`;
    }
    /**
     * 创建 PoW 计算 Worker。
     */
    createPowWorker() {
        const code = `
      self.onmessage = async (e) => {
        const { challengeId, riskNonce, difficulty } = e.data;
        const ts = Date.now();
        let i = 0;
        while (true) {
          const proofNonce = i.toString(16);
          const raw = challengeId + "|" + riskNonce + "|" + proofNonce + "|" + ts;
          const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
          const hash = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
          if (hash.startsWith("0".repeat(difficulty))) {
            self.postMessage({ v: 1, challengeId, riskNonce, proofNonce, ts, hash });
            return;
          }
          i++;
        }
      };
    `;
        return new Worker(URL.createObjectURL(new Blob([code], { type: "application/javascript" })));
    }
    /**
     * 计算行为分数（驻留时长 + 交互次数）。
     */
    behaviorScore() {
        const dwellMs = performance.now() - this.firstInteractionAt;
        return Math.max(1, Math.min(100, Math.floor(dwellMs / 120) + this.interactionCount * 4));
    }
    /**
     * 收集设备基础信息并生成设备哈希。
     */
    async collectDeviceHash() {
        const ua = navigator.userAgent || "";
        const lang = navigator.language || "";
        const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
        const sr = `${screen.width}x${screen.height}x${screen.colorDepth}`;
        return await this.sha256Hex([ua, lang, tz, sr].join("|"));
    }
    /**
     * 规范化 navigator.userAgentData 为 brand/version 串。
     */
    canonicalSecChUaFromNavigator() {
        const uad = navigator.userAgentData;
        if (!uad || !Array.isArray(uad.brands))
            return "";
        return uad.brands
            .map((b) => `${b?.brand || ""}/${b?.version || ""}`)
            .join(",");
    }
    /**
     * 计算 SHA-256 十六进制摘要。
     */
    async sha256Hex(text) {
        const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
        return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    /**
     * 计算 HMAC-SHA256 十六进制签名。
     */
    async hmacSha256Hex(secret, text) {
        const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
        return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    /**
     * 生成固定长度随机十六进制字符串。
     */
    randomHex(bytes) {
        const arr = new Uint8Array(bytes);
        crypto.getRandomValues(arr);
        return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    /**
     * Base64URL 编码。
     */
    base64UrlEncode(text) {
        return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    /**
     * Base64URL 解码。
     */
    base64UrlDecode(text) {
        const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
        return atob(b64 + "===".slice((b64.length + 3) % 4));
    }
}
window.GydevGuardSdk = GydevGuardSdk;
