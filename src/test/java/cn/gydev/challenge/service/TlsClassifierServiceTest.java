package cn.gydev.challenge.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Basic tests for TLS/client-type classifier.
 */
class TlsClassifierServiceTest {

    private final TlsClassifierService service = new TlsClassifierService();

    @Test
    void shouldClassifyCurlAsProgramWhenNoH2() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "curl/8.5.0");

        Map<String, Object> result = service.classify(request);

        assertThat(result.get("type")).isEqualTo("program");
        assertThat(result.get("confidence")).isIn("high", "medium");
    }

    @Test
    void shouldClassifyBrowserWhenBrowserHeadersAndBrowserH2Present() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 Chrome/126.0");
        request.addHeader("Sec-CH-UA", "\"Google Chrome\";v=\"126\"");
        request.addHeader("Sec-Fetch-Site", "none");
        request.addHeader("Accept-Language", "en-US,en;q=0.9");
        request.addHeader("X-H2-FP", "chrome-v1");
        request.addHeader("X-JA3", "ja3-browser");
        request.addHeader("X-JA4", "ja4-browser");

        Map<String, Object> result = service.classify(request);

        assertThat(result.get("type")).isEqualTo("browser");
        assertThat(result.get("confidence")).isEqualTo("high");
    }

    @Test
    void shouldNotTrustForgedBrowserUaWhenProgramH2Present() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 Chrome/126.0");
        request.addHeader("Sec-CH-UA", "\"Google Chrome\";v=\"126\"");
        request.addHeader("X-H2-FP", "curl-h2");
        request.addHeader("X-JA3", "ja3-program");
        request.addHeader("X-JA4", "ja4-program");

        Map<String, Object> result = service.classify(request);

        assertThat(result.get("type")).isIn("program", "unknown");
    }

    @Test
    void shouldDowngradeConfidenceWhenSignalsConflict() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 Chrome/126.0");
        request.addHeader("Sec-CH-UA", "\"Google Chrome\";v=\"126\"");
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("Accept-Language", "en-US");
        request.addHeader("X-H2-FP", "program-h2");

        Map<String, Object> result = service.classify(request);

        assertThat(result.get("type")).isIn("unknown", "program");
        assertThat(result.get("confidence")).isIn("low", "medium");
    }

    @Test
    void shouldNotMarkProgramFingerprintsAsHighConfidenceBrowser() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 Chrome/126.0");
        request.addHeader("Sec-CH-UA", "\"Google Chrome\";v=\"126\"");
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("Accept-Language", "en-US");
        request.addHeader("X-H2-FP", "curl-h2");
        request.addHeader("X-JA3", "ja3-program");
        request.addHeader("X-JA4", "ja4-program");

        Map<String, Object> result = service.classify(request);

        assertThat(result.get("type")).isNotEqualTo("browser");
        assertThat(result.get("confidence")).isNotEqualTo("high");
    }
}
