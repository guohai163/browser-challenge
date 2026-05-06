package cn.gydev.challenge.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Tests for demo self-hosted risk challenge flow with PoW.
 */
class RiskChallengeServiceTest {

    private static final String UA = "Mozilla/5.0 Chrome/126.0";
    private static final String LANG = "en-US,en;q=0.9";
    private static final String SEC_CH_UA = "\"Google Chrome\";v=\"126\"";
    private static final int POW_DIFFICULTY = 4;

    private final RiskChallengeService service = new RiskChallengeService(new TlsClassifierService());

    @Test
    void shouldAcceptValidRiskAndProofToken() throws Exception {
        Map<String, Object> challenge = service.initChallenge();
        MockHttpServletRequest request = baseRequest();
        String riskToken = buildRiskToken(challenge, System.currentTimeMillis(), "risk-nonce-1", 78, false);
        String proofToken = buildProofToken(challenge, "risk-nonce-1", System.currentTimeMillis(), false, false);

        Map<String, Object> result = service.validateSubmission("hello", riskToken, proofToken, request);

        assertThat(result.get("accepted")).isEqualTo(true);
        assertThat(result.get("powVerified")).isEqualTo(true);
    }

    @Test
    void shouldRejectMissingProofToken() throws Exception {
        Map<String, Object> challenge = service.initChallenge();
        MockHttpServletRequest request = baseRequest();
        String riskToken = buildRiskToken(challenge, System.currentTimeMillis(), "risk-nonce-2", 66, false);

        Map<String, Object> result = service.validateSubmission("hello", riskToken, "", request);

        assertThat(result.get("accepted")).isEqualTo(false);
        assertThat(result.get("reason")).isEqualTo("pow_missing");
    }

    @Test
    void shouldRejectExpiredProofToken() throws Exception {
        Map<String, Object> challenge = service.initChallenge();
        MockHttpServletRequest request = baseRequest();
        String riskToken = buildRiskToken(challenge, System.currentTimeMillis(), "risk-nonce-3", 65, false);
        long expiredTs = System.currentTimeMillis() - 90_000L;
        String proofToken = buildProofToken(challenge, "risk-nonce-3", expiredTs, false, false);

        Map<String, Object> result = service.validateSubmission("hello", riskToken, proofToken, request);

        assertThat(result.get("accepted")).isEqualTo(false);
        assertThat(result.get("reason")).isEqualTo("pow_expired");
    }

    @Test
    void shouldRejectReplayProofToken() throws Exception {
        Map<String, Object> challenge = service.initChallenge();
        MockHttpServletRequest request = baseRequest();
        String riskToken = buildRiskToken(challenge, System.currentTimeMillis(), "risk-nonce-4", 70, false);
        String proofToken = buildProofToken(challenge, "risk-nonce-4", System.currentTimeMillis(), false, false);

        Map<String, Object> first = service.validateSubmission("hello", riskToken, proofToken, request);
        Map<String, Object> replay = service.validateSubmission("hello", riskToken, proofToken, request);

        assertThat(first.get("accepted")).isEqualTo(true);
        assertThat(replay.get("accepted")).isEqualTo(false);
        assertThat(replay.get("reason")).isEqualTo("Risk token replay detected");
    }

    @Test
    void shouldRejectInvalidPowDifficulty() throws Exception {
        Map<String, Object> challenge = service.initChallenge();
        MockHttpServletRequest request = baseRequest();
        String riskToken = buildRiskToken(challenge, System.currentTimeMillis(), "risk-nonce-5", 55, false);
        String invalidProofToken = buildProofToken(challenge, "risk-nonce-5", System.currentTimeMillis(), true, false);

        Map<String, Object> result = service.validateSubmission("hello", riskToken, invalidProofToken, request);

        assertThat(result.get("accepted")).isEqualTo(false);
        assertThat(result.get("reason")).isEqualTo("pow_invalid");
    }

    @Test
    void shouldRejectProofChallengeMismatch() throws Exception {
        Map<String, Object> challenge = service.initChallenge();
        Map<String, Object> otherChallenge = service.initChallenge();
        MockHttpServletRequest request = baseRequest();
        String riskToken = buildRiskToken(challenge, System.currentTimeMillis(), "risk-nonce-6", 60, false);
        String wrongChallengeProof = buildProofToken(otherChallenge, "risk-nonce-6", System.currentTimeMillis(), false, false);

        Map<String, Object> result = service.validateSubmission("hello", riskToken, wrongChallengeProof, request);

        assertThat(result.get("accepted")).isEqualTo(false);
        assertThat(result.get("reason")).isEqualTo("pow_invalid");
    }

    @Test
    void shouldRejectWhenTlsFingerprintsAreNotVerifiedAsBrowser() throws Exception {
        Map<String, Object> challenge = service.initChallenge();
        MockHttpServletRequest request = programLikeRequest();
        String riskToken = buildRiskToken(challenge, System.currentTimeMillis(), "risk-nonce-7", 80, false);
        String proofToken = buildProofToken(challenge, "risk-nonce-7", System.currentTimeMillis(), false, false);

        Map<String, Object> result = service.validateSubmission("hello", riskToken, proofToken, request);

        assertThat(result.get("accepted")).isEqualTo(false);
        assertThat(result.get("reason")).isEqualTo("TLS fingerprints are not verified as a real browser");
    }

    private MockHttpServletRequest baseRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", UA);
        request.addHeader("Accept-Language", LANG);
        request.addHeader("Sec-CH-UA", SEC_CH_UA);
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("X-JA3", "ja3-browser");
        request.addHeader("X-JA4", "ja4-browser");
        request.addHeader("X-H2-FP", "chrome-v1");
        return request;
    }

    private MockHttpServletRequest programLikeRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", UA);
        request.addHeader("Accept-Language", LANG);
        request.addHeader("Sec-CH-UA", SEC_CH_UA);
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("X-JA3", "ja3-program");
        request.addHeader("X-JA4", "ja4-program");
        request.addHeader("X-H2-FP", "curl-h2");
        return request;
    }

    private String buildRiskToken(
            Map<String, Object> challenge,
            long ts,
            String nonce,
            int behScore,
            boolean tamperPayloadAfterSign) throws Exception {
        String challengeId = String.valueOf(challenge.get("challengeId"));
        String salt = String.valueOf(challenge.get("salt"));
        String headerPrefix = sha256Hex(UA + "|" + LANG + "|" + SEC_CH_UA).substring(0, 12);
        String fpHash = headerPrefix + ":" + sha256Hex("device-demo").substring(0, 24);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("v", 1);
        payload.put("ts", ts);
        payload.put("challengeId", challengeId);
        payload.put("nonce", nonce);
        payload.put("fpHash", fpHash);
        payload.put("behScore", behScore);
        String signingBase = "1|" + ts + "|" + challengeId + "|" + nonce + "|" + fpHash + "|" + behScore;
        String sig = hmacSha256Hex(salt, signingBase);
        payload.put("sig", sig);

        if (tamperPayloadAfterSign) {
            payload.put("behScore", behScore + 11);
        }

        return base64Url(toJson(payload));
    }

    private String buildProofToken(
            Map<String, Object> challenge,
            String riskNonce,
            long ts,
            boolean forceInvalidDifficulty,
            boolean forceMismatchHash) throws Exception {
        String challengeId = String.valueOf(challenge.get("challengeId"));
        String proofNonce = "0";
        String hash = sha256Hex(challengeId + "|" + riskNonce + "|" + proofNonce + "|" + ts);
        if (!forceInvalidDifficulty) {
            int i = 0;
            while (!hash.startsWith("0".repeat(POW_DIFFICULTY))) {
                i++;
                proofNonce = Integer.toHexString(i);
                hash = sha256Hex(challengeId + "|" + riskNonce + "|" + proofNonce + "|" + ts);
            }
        } else {
            int i = 0;
            while (hash.startsWith("0".repeat(POW_DIFFICULTY))) {
                i++;
                proofNonce = Integer.toHexString(i);
                hash = sha256Hex(challengeId + "|" + riskNonce + "|" + proofNonce + "|" + ts);
            }
        }
        if (forceMismatchHash) {
            hash = "ffff" + hash.substring(4);
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("v", 1);
        payload.put("challengeId", challengeId);
        payload.put("riskNonce", riskNonce);
        payload.put("proofNonce", proofNonce);
        payload.put("ts", ts);
        payload.put("hash", hash);
        return base64Url(toJson(payload));
    }

    private String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private String sha256Hex(String text) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] out = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        return toHex(out);
    }

    private String hmacSha256Hex(String key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return toHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private String toJson(Map<String, Object> payload) {
        if (payload.containsKey("sig")) {
            return "{"
                    + "\"v\":" + payload.get("v") + ","
                    + "\"ts\":" + payload.get("ts") + ","
                    + "\"challengeId\":\"" + payload.get("challengeId") + "\","
                    + "\"nonce\":\"" + payload.get("nonce") + "\","
                    + "\"fpHash\":\"" + payload.get("fpHash") + "\","
                    + "\"behScore\":" + payload.get("behScore") + ","
                    + "\"sig\":\"" + payload.get("sig") + "\""
                    + "}";
        }
        return "{"
                + "\"v\":" + payload.get("v") + ","
                + "\"challengeId\":\"" + payload.get("challengeId") + "\","
                + "\"riskNonce\":\"" + payload.get("riskNonce") + "\","
                + "\"proofNonce\":\"" + payload.get("proofNonce") + "\","
                + "\"ts\":" + payload.get("ts") + ","
                + "\"hash\":\"" + payload.get("hash") + "\""
                + "}";
    }
}
