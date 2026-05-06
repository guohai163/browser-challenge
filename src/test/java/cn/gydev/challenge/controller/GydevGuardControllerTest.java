package cn.gydev.challenge.controller;

import static org.assertj.core.api.Assertions.assertThat;

import cn.gydev.challenge.config.GydevGuardConfiguration;
import cn.gydev.challenge.service.RiskChallengeService;
import cn.gydev.challenge.service.TlsClassifierService;
import cn.gydev.challenge.service.gydev.GydevGuardService;
import cn.gydev.challenge.service.gydev.GydevTokenGuard;
import cn.gydev.challenge.service.gydev.SentinelProofGuard;
import cn.gydev.challenge.service.gydev.TlsFingerprintGuard;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class GydevGuardControllerTest {

    private static final String UA = "Mozilla/5.0 Chrome/126.0";
    private static final String LANG = "en-US,en;q=0.9";
    private static final String SEC_CH_UA = "\"Google Chrome\";v=\"126\"";

    private final TlsClassifierService tlsClassifierService = new TlsClassifierService();
    private final RiskChallengeService riskChallengeService = new RiskChallengeService(tlsClassifierService);
    private final GydevGuardService gydevGuardService = new GydevGuardService(
            new GydevGuardConfiguration().gydevGuardConfig(),
            new TlsFingerprintGuard(tlsClassifierService),
            new GydevTokenGuard(riskChallengeService),
            new SentinelProofGuard()
    );
    private final GydevGuardController controller = new GydevGuardController(gydevGuardService);

    @Test
    void initShouldReturnPowAndGuardConfig() {
        Map<String, Object> challenge = controller.initChallenge();
        assertThat(challenge).containsKey("pow");
        assertThat(challenge).containsKey("guardConfig");
    }

    @Test
    void submitGetAndPostShouldWorkWithNewFieldNames() throws Exception {
        Map<String, Object> challenge = controller.initChallenge();
        String gydevToken = buildGydevToken(challenge, System.currentTimeMillis(), "nonce-x", 75);
        String sentinel = buildSentinelToken(challenge, "nonce-x", System.currentTimeMillis());

        MockHttpServletRequest getRequest = baseRequest();
        getRequest.addHeader("gydev_token", gydevToken);
        getRequest.addHeader("Gydev-Sentinel-Proof-Token", sentinel);
        Map<String, Object> getRes = controller.submitGet("demo", gydevToken, sentinel, getRequest);

        MockHttpServletRequest postRequest = baseRequest();
        postRequest.addHeader("gydev_token", gydevToken);
        postRequest.addHeader("Gydev-Sentinel-Proof-Token", sentinel);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("content", "demo");
        Map<String, Object> postRes = controller.submitPost(body, gydevToken, sentinel, postRequest);

        assertThat(getRes.get("accepted")).isEqualTo(true);
        assertThat(postRes.get("accepted")).isEqualTo(true);
        assertThat(postRes.get("transport")).isEqualTo("post");
    }

    private MockHttpServletRequest baseRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", UA);
        request.addHeader("Accept-Language", LANG);
        request.addHeader("Sec-CH-UA", SEC_CH_UA);
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("X-JA3", "ja3-browser");
        request.addHeader("X-H2-FP", "chrome-v1");
        return request;
    }

    private String buildGydevToken(Map<String, Object> challenge, long ts, String nonce, int behScore) throws Exception {
        String challengeId = String.valueOf(challenge.get("challengeId"));
        String salt = String.valueOf(challenge.get("salt"));
        String headerPrefix = sha256Hex(UA + "|" + LANG + "|" + SEC_CH_UA).substring(0, 12);
        String fpHash = headerPrefix + ":" + sha256Hex("device-demo").substring(0, 24);
        String base = "1|" + ts + "|" + challengeId + "|" + nonce + "|" + fpHash + "|" + behScore;
        String sig = hmacSha256Hex(salt, base);
        String json = "{"
                + "\"v\":1,"
                + "\"ts\":" + ts + ","
                + "\"challengeId\":\"" + challengeId + "\","
                + "\"nonce\":\"" + nonce + "\","
                + "\"fpHash\":\"" + fpHash + "\","
                + "\"behScore\":" + behScore + ","
                + "\"sig\":\"" + sig + "\""
                + "}";
        return b64(json);
    }

    private String buildSentinelToken(Map<String, Object> challenge, String riskNonce, long ts) throws Exception {
        String challengeId = String.valueOf(challenge.get("challengeId"));
        int i = 0;
        String nonce;
        String hash;
        do {
            nonce = Integer.toHexString(i++);
            hash = sha256Hex(challengeId + "|" + riskNonce + "|" + nonce + "|" + ts);
        } while (!hash.startsWith("0000"));
        String json = "{"
                + "\"v\":1,"
                + "\"challengeId\":\"" + challengeId + "\","
                + "\"riskNonce\":\"" + riskNonce + "\","
                + "\"proofNonce\":\"" + nonce + "\","
                + "\"ts\":" + ts + ","
                + "\"hash\":\"" + hash + "\""
                + "}";
        return b64(json);
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

    private String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
