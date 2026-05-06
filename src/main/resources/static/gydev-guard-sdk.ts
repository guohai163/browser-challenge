type GydevInitResponse = {
  challengeId: string;
  expiresAt: string;
  salt: string;
  publicParams: Record<string, unknown>;
  pow: { algo: string; difficulty: number; maxAgeMs: number };
};

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

type SubmitPayload = {
  content: string;
  Gydev-Token: string;
  "Gydev-Sentinel-Proof-Token": string;
};

type GydevState = {
  challengeId: string;
  salt: string;
  expiresAtMs: number;
  pow: { algo: string; difficulty: number; maxAgeMs: number };
};

export class GydevGuardSdk {
  private config: Required<GydevConfig>;
  private state: GydevState;
  private firstInteractionAt = performance.now();
  private interactionCount = 0;
  private powWorker: Worker;

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

  async createGydevToken() {
    if (!this.config.features.gydevToken) return "";
    if (!this.state.challengeId || Date.now() > this.state.expiresAtMs) {
      await this.initChallenge();
    }
    const ua = navigator.userAgent || "";
    const lang = navigator.language || "";
    const secChUa = (navigator as any).userAgentData
      ? JSON.stringify((navigator as any).userAgentData.brands || [])
      : "";
    const headerPrefix = (await this.sha256Hex(`${ua}|${lang}|${secChUa}`)).slice(0, 12);
    const fpHash = `${headerPrefix}:${(await this.collectDeviceHash()).slice(0, 24)}`;
    const payload: any = {
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

  async submitGet(content: string, gydevToken: string, sentinelToken: string) {
    const url = new URL(this.withBase(this.config.endpoints.submitGet), window.location.origin);
    url.searchParams.set("content", content);
    const res = await fetch(url.toString(), {
      headers: {
        Gydev-Token: gydevToken,
        "Gydev-Sentinel-Proof-Token": sentinelToken,
      },
    });
    return await res.json();
  }

  async submitPost(content: string, gydevToken: string, sentinelToken: string) {
    const payload: SubmitPayload = {
      content,
    };
    const res = await fetch(this.withBase(this.config.endpoints.submitPost), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Gydev-Token: gydevToken,
        "Gydev-Sentinel-Proof-Token": sentinelToken,
      },
      body: JSON.stringify(payload),
    });
    return await res.json();
  }

  private withBase(path: string) {
    return `${this.config.baseUrl}${path}`;
  }

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

  private behaviorScore() {
    const dwellMs = performance.now() - this.firstInteractionAt;
    return Math.max(1, Math.min(100, Math.floor(dwellMs / 120) + this.interactionCount * 4));
  }

  private async collectDeviceHash() {
    const ua = navigator.userAgent || "";
    const lang = navigator.language || "";
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
    const sr = `${screen.width}x${screen.height}x${screen.colorDepth}`;
    return await this.sha256Hex([ua, lang, tz, sr].join("|"));
  }

  private async sha256Hex(text: string) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

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

  private randomHex(bytes: number) {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  private base64UrlEncode(text: string) {
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  private base64UrlDecode(text: string) {
    const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
    return atob(b64 + "===".slice((b64.length + 3) % 4));
  }
}

(window as any).GydevGuardSdk = GydevGuardSdk;
