package cn.gydev.challenge.controller;

import static org.assertj.core.api.Assertions.assertThat;

import cn.gydev.challenge.service.TlsClassifierService;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Controller-level contract test by direct invocation.
 */
class TlsControllerTest {

    private final TlsController controller = new TlsController(new TlsClassifierService());

    @Test
    void shouldReturnEnhancedFields() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 Chrome/126.0");
        request.addHeader("Sec-CH-UA", "\"Google Chrome\";v=\"126\"");
        request.addHeader("X-H2-FP", "chrome-v1");
        request.addHeader("X-H2-SETTINGS", "settings-a");
        request.addHeader("X-H2-WINDOW", "65535");
        request.addHeader("X-H2-PRIORITY", "p1");
        request.addHeader("X-JA3", "ja3-browser");

        Map<String, Object> result = controller.tls(request);
        @SuppressWarnings("unchecked")
        Map<String, Object> fingerprints = (Map<String, Object>) result.get("fingerprints");
        @SuppressWarnings("unchecked")
        Map<String, Object> scoreBreakdown = (Map<String, Object>) result.get("scoreBreakdown");
        @SuppressWarnings("unchecked")
        Map<String, Object> signals = (Map<String, Object>) result.get("signals");
        @SuppressWarnings("unchecked")
        Map<String, Object> h2Details = (Map<String, Object>) signals.get("h2Details");

        assertThat(result).containsKey("type");
        assertThat(result).containsKey("confidence");
        assertThat(result).containsKey("reason");
        assertThat(result).containsKey("scoreBreakdown");
        assertThat(result).containsKey("fingerprints");
        assertThat(result).containsKey("signals");
        assertThat(scoreBreakdown).containsKey("h2");
        assertThat(scoreBreakdown).containsKey("tls");
        assertThat(scoreBreakdown).containsKey("header");
        assertThat(scoreBreakdown).containsKey("total");
        assertThat(fingerprints.get("h2")).isEqualTo("chrome-v1");
        assertThat(h2Details.get("settings")).isEqualTo("settings-a");
    }
}
