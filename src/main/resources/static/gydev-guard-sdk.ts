/**
 * challenge/init 接口响应结构。
 */
type GydevInitResponse = {
  challengeId: string;
  expiresAt: string;
  salt: string;
  publicParams: Record<string, unknown>;
  pow: { algo: string; difficulty: number; maxAgeMs: number };
};

/**
 * SDK 初始化配置。
 */
type GydevConfig = {
  baseUrl?: string;
  endpoints?: {
    initChallenge?: string;
    submitGet?: string;
    submitPost?: string;
  };
  features?: {
    tlsFingerprint?: boolean;
    h2Fingerprint?: boolean;
    gydevToken?: boolean;
    sentinelProofToken?: boolean;
  };
};

/**
 * POST 提交体结构。
 */
type SubmitPayload = {
  content: string;
};

/**
 * SDK 运行时状态。
 */
type GydevState = {
  challengeId: string;
  salt: string;
  expiresAtMs: number;
  pow: { algo: string; difficulty: number; maxAgeMs: number };
};

/**
 * Gydev 前端防护 SDK。
 * <p>
 * 负责 challenge 初始化、Gydev-Token 生成、PoW 计算与 GET/POST 提交封装。
 */
class GydevGuardSdk {
  private config: Required<GydevConfig>;
  private state: GydevState;
  private firstInteractionAt = performance.now();
  private interactionCount = 0;
  private powWorker: Worker;

  /**
   * 创建 SDK 实例并初始化默认配置与交互统计监听。
   */
  constructor() {
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
  init(config: GydevConfig) {
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
  async initChallenge(): Promise<GydevInitResponse> {
    const res = await fetch(this.withBase(this.config.endpoints.initChallenge));
    if (!res.ok) throw new Error("init challenge failed");
    const data = (await res.json()) as GydevInitResponse;
    this.state.challengeId = data.challengeId;
    this.state.salt = data.salt;
    this.state.expiresAtMs = Date.parse(data.expiresAt);
    if (data.pow) this.state.pow = data.pow;
    return data;
  }

  /**
   * 生成 Gydev-Token。
   *
   * @returns Gydev-Token；若功能关闭则返回空字符串
   */
  async createGydevToken() {
    // 功能开关关闭时直接返回空字符串，调用方按“跳过校验”分支处理。
    if (!this.config.features.gydevToken) return "";
    // 首次调用或挑战过期时，先向后端拉取新的 challenge 参数。
    if (!this.state.challengeId || Date.now() > this.state.expiresAtMs) {
      await this.initChallenge();
    }
    // 采集与请求头弱绑定相关的浏览器特征。
    const ua = navigator.userAgent || "";
    const lang = navigator.language || "";
    const secChUa = this.canonicalSecChUaFromNavigator();
    // 与服务端规则保持一致：sha256(ua|lang|secChUa) 的前 12 位作为 headerPrefix。
    const headerPrefix = (await this.sha256Hex(`${ua}|${lang}|${secChUa}`)).slice(0, 12);
    // fpHash 格式固定为 "headerPrefix:deviceHash前缀"。
    const fpHash = `${headerPrefix}:${(await this.collectDeviceHash()).slice(0, 24)}`;
    // 组装待签名 token 载荷。
    const payload: any = {
      v: 1,
      ts: Date.now(),
      challengeId: this.state.challengeId,
      nonce: this.randomHex(8),
      fpHash,
      behScore: this.behaviorScore(),
    };
    // 服务端按同顺序拼接签名原文，字段顺序不能改。
    const base = `${payload.v}|${payload.ts}|${payload.challengeId}|${payload.nonce}|${payload.fpHash}|${payload.behScore}`;
    // 用 challenge 返回的 salt 计算 HMAC-SHA256 签名。
    payload.sig = await this.hmacSha256Hex(this.state.salt, base);
    // 最终以 Base64URL(JSON) 形式输出 Gydev-Token。
    return this.base64UrlEncode(JSON.stringify(payload));
  }

  /**
   * 生成 Gydev-Sentinel-Proof-Token（PoW）。
   *
   * @param gydevToken 已生成的 Gydev-Token
   * @returns Proof Token；若功能关闭则返回空字符串
   */
  async createSentinelProofToken(gydevToken: string) {
    if (!this.config.features.sentinelProofToken) return "";
    const parsed = JSON.parse(this.base64UrlDecode(gydevToken));
    return await new Promise<string>((resolve, reject) => {
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
  async submitGet(content: string, gydevToken: string, sentinelToken: string) {
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
  async submitPost(content: string, gydevToken: string, sentinelToken: string) {
    const payload: SubmitPayload = {
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
  private withBase(path: string) {
    return `${this.config.baseUrl}${path}`;
  }

  /**
   * 创建 PoW 计算 Worker。
   */
  private createPowWorker() {
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
  private behaviorScore() {
    const dwellMs = performance.now() - this.firstInteractionAt;
    return Math.max(1, Math.min(100, Math.floor(dwellMs / 120) + this.interactionCount * 4));
  }

  /**
   * 收集设备基础信息并生成设备哈希。
   */
  private async collectDeviceHash() {
    const ua = navigator.userAgent || "";
    const lang = navigator.language || "";
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
    const sr = `${screen.width}x${screen.height}x${screen.colorDepth}`;
    return await this.sha256Hex([ua, lang, tz, sr].join("|"));
  }

  /**
   * 规范化 navigator.userAgentData 为 brand/version 串。
   */
  private canonicalSecChUaFromNavigator() {
    const uad = (navigator as any).userAgentData;
    if (!uad || !Array.isArray(uad.brands)) return "";
    return uad.brands
      .map((b: any) => `${b?.brand || ""}/${b?.version || ""}`)
      .join(",");
  }

  /**
   * 计算 SHA-256 十六进制摘要。
   */
  private async sha256Hex(text: string) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * 计算 HMAC-SHA256 十六进制签名。
   */
  private async hmacSha256Hex(secret: string, text: string) {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
    return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * 生成固定长度随机十六进制字符串。
   */
  private randomHex(bytes: number) {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Base64URL 编码。
   */
  private base64UrlEncode(text: string) {
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  /**
   * Base64URL 解码。
   */
  private base64UrlDecode(text: string) {
    const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
    return atob(b64 + "===".slice((b64.length + 3) % 4));
  }
}

(window as any).GydevGuardSdk = GydevGuardSdk;
