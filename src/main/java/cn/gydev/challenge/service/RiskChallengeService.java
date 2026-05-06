package cn.gydev.challenge.service;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.boot.json.JsonParser;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.stereotype.Service;

/**
 * 演示用风险挑战服务，负责前端 token 生成参数下发与服务端校验。
 */
@Service
public class RiskChallengeService {

    private static final long CHALLENGE_TTL_MS = 120_000L;
    private static final long TOKEN_MAX_AGE_MS = 120_000L;
    private static final long POW_MAX_AGE_MS = 60_000L;
    private static final int HEADER_HASH_PREFIX_LEN = 12;
    private static final int TOKEN_VERSION = 1;
    private static final int PROOF_TOKEN_VERSION = 1;
    private static final int POW_DIFFICULTY = 4;
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final String POW_ALGO = "sha256-prefix-zero";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final JsonParser JSON_PARSER = JsonParserFactory.getJsonParser();

    private final ConcurrentMap<String, ChallengeSession> sessions = new ConcurrentHashMap<>();
    private final Set<String> usedRiskNonces = ConcurrentHashMap.newKeySet();
    private final Set<String> usedProofNonces = ConcurrentHashMap.newKeySet();
    private final TlsClassifierService tlsClassifierService;

    public RiskChallengeService(TlsClassifierService tlsClassifierService) {
        this.tlsClassifierService = tlsClassifierService;
    }

    /**
     * 初始化短时有效挑战，用于前端生成 token。
     *
     * @return 挑战参数
     */
    public Map<String, Object> initChallenge() {
        // 每次初始化前先清理过期会话，避免内存中残留无效挑战数据。
        cleanupExpired();

        // 生成挑战标识与会话密钥：challengeId 用于关联本次挑战，sessionKey 用于后续签名校验。
        String challengeId = randomHex(16);
        String sessionKey = randomHex(32);
        long now = System.currentTimeMillis();
        long expiresAt = now + CHALLENGE_TTL_MS;

        // 将挑战会话缓存到内存，供提交阶段按 challengeId 回查。
        sessions.put(challengeId, new ChallengeSession(challengeId, sessionKey, expiresAt));

        // 组织前端生成 Gydev-Token 所需的公开参数。
        Map<String, Object> publicParams = new LinkedHashMap<>();
        publicParams.put("tokenVersion", TOKEN_VERSION);
        publicParams.put("maxAgeMs", TOKEN_MAX_AGE_MS);
        publicParams.put("fpHashFormat", "headerPrefix:deviceHash");
        // 组织前端计算 Sentinel PoW 所需参数。
        Map<String, Object> powParams = new LinkedHashMap<>();
        powParams.put("algo", POW_ALGO);
        powParams.put("difficulty", POW_DIFFICULTY);
        powParams.put("maxAgeMs", POW_MAX_AGE_MS);

        // 返回统一挑战载荷：包含 challengeId、过期时间、salt(会话密钥) 与公共规则参数。
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("challengeId", challengeId);
        result.put("expiresAt", Instant.ofEpochMilli(expiresAt).toString());
        result.put("salt", sessionKey);
        result.put("publicParams", publicParams);
        result.put("pow", powParams);
        return result;
    }

    /**
     * 校验风险 token（含 PoW）并给出是否放行的判定。
     *
     * @param content 业务内容
     * @param riskToken 前端生成的风险 token
     * @param request HTTP 请求
     * @return 判定结果
     */
    public Map<String, Object> validateSubmission(
            String content,
            String riskToken,
            String proofToken,
            HttpServletRequest request) {
        return validateSubmissionInternal(content, riskToken, proofToken, request, true);
    }

    /**
     * 校验 Gydev Token，但跳过 Sentinel Proof 校验。
     *
     * @param content 业务内容
     * @param riskToken 前端生成的风险 token
     * @param request HTTP 请求
     * @return 判定结果
     */
    public Map<String, Object> validateSubmissionWithoutPow(
            String content,
            String riskToken,
            HttpServletRequest request) {
        return validateSubmissionInternal(content, riskToken, "", request, false);
    }

    private Map<String, Object> validateSubmissionInternal(
            String content,
            String riskToken,
            String proofToken,
            HttpServletRequest request,
            boolean enforcePow) {
        cleanupExpired();

        if (content == null || content.isBlank()) {
            return decision(false, false, "high", "Content is empty", 0L);
        }
        if (riskToken == null || riskToken.isBlank()) {
            return decision(false, false, "high", "Risk token is missing", 0L);
        }
        if (enforcePow && (proofToken == null || proofToken.isBlank())) {
            return decision(false, false, "high", "pow_missing", 0L);
        }

        TokenPayload payload;
        try {
            payload = parseTokenPayload(riskToken);
        } catch (Exception ex) {
            return decision(false, false, "high", "Risk token format is invalid", 0L);
        }

        if (payload.v != TOKEN_VERSION) {
            return decision(false, false, "high", "Unsupported token version", 0L);
        }

        long now = System.currentTimeMillis();
        long ageMs = Math.max(0L, now - payload.ts);
        if (ageMs > TOKEN_MAX_AGE_MS) {
            return decision(false, false, "high", "Risk token is expired", ageMs);
        }

        ChallengeSession session = sessions.get(payload.challengeId);
        if (session == null || session.expiresAtMs < now) {
            return decision(false, false, "high", "Challenge is missing or expired", ageMs);
        }

        String nonceKey = payload.challengeId + ":" + payload.nonce;
        // Nonce 去重用于防止挑战窗口内重放。
        if (!usedRiskNonces.add(nonceKey)) {
            return decision(false, false, "high", "Risk token replay detected", ageMs);
        }

        if (!verifyFpWeakBinding(payload.fpHash, request)) {
            return decision(false, false, "high", "Fingerprint/header weak binding mismatch", ageMs);
        }

        String signingBase = signingBase(payload);
        String expectedSig = hmacHex(session.sessionKey, signingBase);
        if (!Objects.equals(expectedSig, payload.sig)) {
            return decision(false, false, "high", "Risk token signature mismatch", ageMs);
        }

        boolean powVerified = !enforcePow;
        if (enforcePow) {
            ProofTokenPayload proof;
            try {
                proof = parseProofTokenPayload(proofToken);
            } catch (Exception ex) {
                return decision(false, false, "high", "pow_invalid", ageMs);
            }

            if (proof.v != PROOF_TOKEN_VERSION) {
                return decision(false, false, "high", "pow_invalid", ageMs);
            }
            if (!payload.challengeId.equals(proof.challengeId) || !payload.nonce.equals(proof.riskNonce)) {
                return decision(false, false, "high", "pow_invalid", ageMs);
            }
            long proofAgeMs = Math.max(0L, now - proof.ts);
            if (proofAgeMs > POW_MAX_AGE_MS) {
                return decision(false, false, "high", "pow_expired", ageMs);
            }
            String proofNonceKey = proof.challengeId + ":" + proof.proofNonce;
            // PoW nonce 同样只允许一次，防止 proof token 重放。
            if (!usedProofNonces.add(proofNonceKey)) {
                return decision(false, false, "high", "pow_replay", ageMs);
            }
            String expectedHash = sha256Hex(proof.challengeId + "|" + proof.riskNonce + "|" + proof.proofNonce + "|" + proof.ts);
            if (!hasLeadingZeros(expectedHash, POW_DIFFICULTY) || !expectedHash.equals(proof.hash)) {
                return decision(false, false, "high", "pow_invalid", ageMs);
            }
            powVerified = true;
        }

        String riskLevel = "low";
        String reason = "Challenge passed";

        @SuppressWarnings("unchecked")
        Map<String, Object> tls = (Map<String, Object>) tlsClassifierService.classify(request);
        if (!hasRequiredTlsFingerprints(tls)) {
            return decision(false, powVerified, "high", "Missing required JA3/JA4/H2 fingerprints", ageMs);
        }
        if (!isVerifiedBrowserClient(tls)) {
            return decision(false, powVerified, "high", "TLS fingerprints are not verified as a real browser", ageMs);
        }
        String tlsType = String.valueOf(tls.getOrDefault("type", "unknown"));

        if (payload.behScore < 35) {
            riskLevel = "medium";
            reason = "Challenge passed with low behavior score";
        }

        Map<String, Object> result = decision(true, powVerified, riskLevel, reason, ageMs);
        result.put("tlsType", tlsType);
        return result;
    }

    /**
     * 严格校验 TLS/H2 指纹是否齐全且基本有效。
     * 当前策略要求 JA3、JA4、H2 三项均存在，缺一不可。
     *
     * @param tlsClassifierResult TLS 分类结果
     * @return 满足必填要求返回 true
     */
    @SuppressWarnings("unchecked")
    private boolean hasRequiredTlsFingerprints(Map<String, Object> tlsClassifierResult) {
        if (tlsClassifierResult == null) {
            return false;
        }
        Object fingerprintsObj = tlsClassifierResult.get("fingerprints");
        if (!(fingerprintsObj instanceof Map<?, ?> fingerprints)) {
            return false;
        }

        Object ja3Obj = fingerprints.get("ja3");
        Object ja4Obj = fingerprints.get("ja4");
        String ja3 = ja3Obj == null ? "" : String.valueOf(ja3Obj).trim();
        String ja4 = ja4Obj == null ? "" : String.valueOf(ja4Obj).trim();

        Object h2Obj = fingerprints.get("h2");
        String h2 = h2Obj == null ? "" : String.valueOf(h2Obj).trim();

        return isValidFingerprintValue(ja3) && isValidFingerprintValue(ja4) && isValidFingerprintValue(h2);
    }

    /**
     * 真实浏览器判定：
     * 1) 分类结果必须为 browser
     * 2) 置信度必须为 high（要求 H2 与 JA3/JA4 信号共同支撑）
     */
    private boolean isVerifiedBrowserClient(Map<String, Object> tlsClassifierResult) {
        if (tlsClassifierResult == null) {
            return false;
        }
        String type = String.valueOf(tlsClassifierResult.getOrDefault("type", "unknown"));
        String confidence = String.valueOf(tlsClassifierResult.getOrDefault("confidence", "low"));
        return "browser".equals(type) && "high".equals(confidence);
    }

    /**
     * 指纹值基础有效性检查：
     * 非空且不为 unknown / n/a / null 等占位值。
     */
    private boolean isValidFingerprintValue(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String lower = value.trim().toLowerCase(Locale.ROOT);
        return !("unknown".equals(lower) || "n/a".equals(lower) || "null".equals(lower) || "-".equals(lower));
    }

    /**
     * 构建统一判定结果结构，供控制层与封装层复用。
     *
     * @param accepted 是否放行
     * @param powVerified PoW 是否通过（或被跳过）
     * @param riskLevel 最终风险等级
     * @param reason 判定原因
     * @param tokenAgeMs token 年龄（毫秒）
     * @return 判定结果
     */
    private Map<String, Object> decision(boolean accepted, boolean powVerified, String riskLevel, String reason, long tokenAgeMs) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("accepted", accepted);
        result.put("powVerified", powVerified);
        result.put("riskLevel", riskLevel);
        result.put("reason", reason);
        result.put("tokenAgeMs", tokenAgeMs);
        return result;
    }

    /**
     * 校验 token 中 fpHash 前缀与当前请求头之间的弱绑定关系。
     *
     * @param fpHash token 内的 fpHash
     * @param request 当前请求
     * @return 前缀匹配则返回 true
     */
    private boolean verifyFpWeakBinding(String fpHash, HttpServletRequest request) {
        if (fpHash == null || fpHash.isBlank() || !fpHash.contains(":")) {
            return false;
        }
        String[] parts = fpHash.split(":", 2);
        String prefix = parts[0];

        String ua = header(request, "User-Agent");
        String lang = canonicalPrimaryLanguage(header(request, "Accept-Language"));
        String secChUa = canonicalSecChUa(header(request, "Sec-CH-UA"));
        String expected = sha256Hex(ua + "|" + lang + "|" + secChUa).substring(0, HEADER_HASH_PREFIX_LEN);
        return expected.equals(prefix);
    }

    /**
     * 规范化 Accept-Language，仅保留主语言标识。
     *
     * @param acceptLanguage 原始 Accept-Language 头
     * @return 规范化后的主语言值
     */
    private String canonicalPrimaryLanguage(String acceptLanguage) {
        if (acceptLanguage == null || acceptLanguage.isBlank()) {
            return "";
        }
        String first = acceptLanguage.split(",")[0].trim();
        int qIdx = first.indexOf(";q=");
        if (qIdx > 0) {
            return first.substring(0, qIdx).trim();
        }
        return first;
    }

    /**
     * 规范化 Sec-CH-UA 为稳定的 brand/version 组合，保证哈希一致性。
     *
     * @param secChUaHeader 原始 Sec-CH-UA 头
     * @return 规范化后的 Sec-CH-UA 字符串
     */
    private String canonicalSecChUa(String secChUaHeader) {
        if (secChUaHeader == null || secChUaHeader.isBlank()) {
            return "";
        }
        List<String> items = new ArrayList<>();
        String[] parts = secChUaHeader.split(",");
        for (String part : parts) {
            String p = part.trim();
            int q1 = p.indexOf('"');
            int q2 = p.indexOf('"', q1 + 1);
            int vPos = p.indexOf(";v=");
            if (q1 >= 0 && q2 > q1 && vPos > q2) {
                String brand = p.substring(q1 + 1, q2);
                String versionRaw = p.substring(vPos + 3).trim();
                String version = stripQuotes(versionRaw);
                items.add(brand + "/" + version);
            }
        }
        return String.join(",", items);
    }

    /**
     * 去除字符串两端包裹的引号（如果存在）。
     *
     * @param input 原始值
     * @return 去引号后的值
     */
    private String stripQuotes(String input) {
        if (input == null || input.isBlank()) {
            return "";
        }
        String out = input.trim();
        if (out.length() >= 2 && out.startsWith("\"") && out.endsWith("\"")) {
            return out.substring(1, out.length() - 1);
        }
        return out;
    }

    /**
     * 从 Base64URL JSON 解析 Gydev-Token 载荷。
     *
     * @param riskToken Gydev Token 字符串
     * @return 解析后的 token 载荷
     */
    private TokenPayload parseTokenPayload(String riskToken) {
        String json = new String(Base64.getUrlDecoder().decode(riskToken), StandardCharsets.UTF_8);
        Map<String, Object> map = JSON_PARSER.parseMap(json);
        int v = intValue(map.get("v"));
        long ts = longValue(map.get("ts"));
        String challengeId = stringValue(map.get("challengeId"));
        String nonce = stringValue(map.get("nonce"));
        String fpHash = stringValue(map.get("fpHash"));
        int behScore = intValue(map.get("behScore"));
        String sig = stringValue(map.get("sig")).toLowerCase(Locale.ROOT);
        return new TokenPayload(v, ts, challengeId, nonce, fpHash, behScore, sig);
    }

    /**
     * 从 Base64URL JSON 解析 Gydev-Sentinel-Proof-Token 载荷。
     *
     * @param proofToken Proof Token 字符串
     * @return 解析后的 proof 载荷
     */
    private ProofTokenPayload parseProofTokenPayload(String proofToken) {
        String json = new String(Base64.getUrlDecoder().decode(proofToken), StandardCharsets.UTF_8);
        Map<String, Object> map = JSON_PARSER.parseMap(json);
        int v = intValue(map.get("v"));
        String challengeId = stringValue(map.get("challengeId"));
        String riskNonce = stringValue(map.get("riskNonce"));
        String proofNonce = stringValue(map.get("proofNonce"));
        long ts = longValue(map.get("ts"));
        String hash = stringValue(map.get("hash")).toLowerCase(Locale.ROOT);
        return new ProofTokenPayload(v, challengeId, riskNonce, proofNonce, ts, hash);
    }

    /**
     * 重建前后端一致的签名原文。
     *
     * @param payload 解析后的 token 载荷
     * @return 签名原文
     */
    private String signingBase(TokenPayload payload) {
        return payload.v + "|" + payload.ts + "|" + payload.challengeId + "|" + payload.nonce + "|"
                + payload.fpHash + "|" + payload.behScore;
    }

    private int intValue(Object value) {
        return Integer.parseInt(String.valueOf(value));
    }

    private long longValue(Object value) {
        return Long.parseLong(String.valueOf(value));
    }

    private String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private String header(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return value == null ? "" : value.trim();
    }

    /**
     * 计算十六进制格式的 HMAC-SHA256。
     *
     * @param secret 签名密钥
     * @param data 原文
     * @return 十六进制摘要
     */
    private String hmacHex(String secret, String data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGO));
            return toHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to calculate HMAC", ex);
        }
    }

    /**
     * 计算十六进制格式的 SHA-256 摘要。
     *
     * @param data 原文
     * @return 十六进制摘要
     */
    private String sha256Hex(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHex(digest.digest(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to calculate sha256", ex);
        }
    }

    /**
     * 将字节数组转为小写十六进制字符串。
     *
     * @param bytes 源字节数组
     * @return 小写十六进制字符串
     */
    private String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * 生成固定字节长度的随机十六进制字符串。
     *
     * @param byteLength 随机字节长度
     * @return 随机十六进制字符串
     */
    private String randomHex(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SECURE_RANDOM.nextBytes(bytes);
        return toHex(bytes);
    }

    /**
     * 清理过期挑战会话，控制内存占用。
     */
    private void cleanupExpired() {
        long now = System.currentTimeMillis();
        sessions.values().removeIf(s -> s.expiresAtMs < now);
    }

    /**
     * 检查十六进制哈希前缀是否满足指定数量的 0。
     *
     * @param hex 哈希值
     * @param difficulty 前导零难度
     * @return 满足 PoW 难度要求时返回 true
     */
    private boolean hasLeadingZeros(String hex, int difficulty) {
        if (hex == null || hex.length() < difficulty) {
            return false;
        }
        for (int i = 0; i < difficulty; i++) {
            if (hex.charAt(i) != '0') {
                return false;
            }
        }
        return true;
    }

    private record ChallengeSession(String challengeId, String sessionKey, long expiresAtMs) {
    }

    private record TokenPayload(
            int v,
            long ts,
            String challengeId,
            String nonce,
            String fpHash,
            int behScore,
            String sig
    ) {
    }

    private record ProofTokenPayload(
            int v,
            String challengeId,
            String riskNonce,
            String proofNonce,
            long ts,
            String hash
    ) {
    }
}
