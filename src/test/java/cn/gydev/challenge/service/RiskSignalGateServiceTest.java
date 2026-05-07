package cn.gydev.challenge.service;

import static org.assertj.core.api.Assertions.assertThat;

import cn.gydev.challenge.config.RiskGateProperties;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class RiskSignalGateServiceTest {

    @Test
    void shouldFailWhenJa3MissingAndRequireJa3Enabled() {
        RiskGateProperties properties = new RiskGateProperties();
        properties.setEnabled(true);
        properties.setRequireJa3(true);
        StubRiskFingerprintWhitelistRepository repo = new StubRiskFingerprintWhitelistRepository();
        RiskSignalGateService service = new RiskSignalGateService(properties, repo);

        MockHttpServletRequest request = browserRequest();
        Map<String, Object> tls = tlsFingerprints("", "ja4-browser", "chrome-v1");

        Map<String, Object> result = service.verify(request, tls);

        assertThat(result.get("gatePassed")).isEqualTo(false);
        @SuppressWarnings("unchecked")
        List<String> failures = (List<String>) result.get("gateFailures");
        assertThat(failures).contains("missing_tls_fingerprint");
        assertThat(repo.isWhitelistedWithoutJa3Called).isFalse();
    }

    @Test
    void shouldIgnoreJa3WhenRequireJa3Disabled() {
        RiskGateProperties properties = new RiskGateProperties();
        properties.setEnabled(true);
        properties.setRequireJa3(false);
        StubRiskFingerprintWhitelistRepository repo = new StubRiskFingerprintWhitelistRepository();
        repo.whitelistedWithoutJa3 = true;
        RiskSignalGateService service = new RiskSignalGateService(properties, repo);

        MockHttpServletRequest request = browserRequest();
        Map<String, Object> tls = tlsFingerprints("", "ja4-browser", "chrome-v1");

        Map<String, Object> result = service.verify(request, tls);

        assertThat(result.get("gatePassed")).isEqualTo(true);
        @SuppressWarnings("unchecked")
        List<String> failures = (List<String>) result.get("gateFailures");
        assertThat(failures).isEmpty();
        assertThat(repo.isWhitelistedWithoutJa3Called).isTrue();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> tlsFingerprints(String ja3, String ja4, String h2) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> fps = new LinkedHashMap<>();
        fps.put("ja3", ja3);
        fps.put("ja4", ja4);
        fps.put("h2", h2);
        out.put("fingerprints", fps);
        return out;
    }

    private MockHttpServletRequest browserRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 Chrome/126.0.0.0");
        request.setRemoteAddr("127.0.0.1");
        return request;
    }

    private static final class StubRiskFingerprintWhitelistRepository extends RiskFingerprintWhitelistRepository {
        private boolean isWhitelistedWithoutJa3Called;
        private boolean whitelistedWithoutJa3;

        private StubRiskFingerprintWhitelistRepository() {
            super(null);
        }

        @Override
        public boolean isWhitelisted(String browserFamily, int majorVersion, String ja3Md5Normalized, String ja4, String h2) {
            return false;
        }

        @Override
        public boolean isWhitelistedWithoutJa3(String browserFamily, int majorVersion, String ja4, String h2) {
            isWhitelistedWithoutJa3Called = true;
            return whitelistedWithoutJa3;
        }
    }
}
