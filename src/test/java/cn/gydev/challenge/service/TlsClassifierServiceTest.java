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

    @Test
    void shouldClassifyBrowserWhenH2SettingsMatchRealBrowserPattern() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36");
        request.addHeader("Sec-CH-UA", "\"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"145\", \"Chromium\";v=\"145\"");
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8");
        request.addHeader("X-H2-FP", "a0785471c8d36ae639d9cbfcca658ff9c7da11651a17a96e80552c533e50b4e5");
        request.addHeader("X-H2-SETTINGS", "header_table_size=65536;enable_push=0;initial_window_size=6291456;max_header_list_size=262144");
        request.addHeader("X-H2-WINDOW", "15663105");
        request.addHeader("X-H2-PRIORITY", "");
        request.addHeader("X-JA3", "d2676e052b6564b3ecc88bd70305e4b6");
        request.addHeader("X-JA4", "t13d1516h2_8daaf6152771_d8a2da3f94cd");

        Map<String, Object> result = service.classify(request);

        assertThat(result.get("type")).isEqualTo("browser");
        assertThat(result.get("confidence")).isEqualTo("high");
    }

    @Test
    void shouldClassifySafariAsBrowserWhenH2SettingsMatchSafariPattern() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15");
        request.addHeader("Sec-CH-UA", "\"Not:A-Brand\";v=\"99\", \"Safari\";v=\"18\"");
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("Accept-Language", "zh-CN,zh-Hans;q=0.9");
        request.addHeader("X-H2-FP", "40873289afe3a13e813c7905c2ee9e746d7e60f3d4d7dd9dab161e912193e316");
        request.addHeader("X-H2-SETTINGS", "enable_push=0;max_concurrent_streams=100;initial_window_size=2097152;unknown=1");
        request.addHeader("X-H2-WINDOW", "10420225");
        request.addHeader("X-H2-PRIORITY", "");
        request.addHeader("X-JA3", "bae146cc2528b49cbcd78c00475566a7");
        request.addHeader("X-JA4", "t13d2014h2_a09f3c656075_e42f34c56612");

        Map<String, Object> result = service.classify(request);

        assertThat(result.get("type")).isEqualTo("browser");
        assertThat(result.get("confidence")).isEqualTo("high");
    }

    @Test
    void shouldClassifyIosSafariAsBrowserWhenSafariH2SettingsPresentWithDifferentWindow() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1");
        request.addHeader("Sec-CH-UA", "\"Not:A-Brand\";v=\"99\", \"Safari\";v=\"18\"");
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("Accept-Language", "zh-CN,zh-Hans;q=0.9");
        request.addHeader("X-H2-FP", "ios-safari-h2-hash");
        request.addHeader("X-H2-SETTINGS", "enable_push=0;max_concurrent_streams=100;initial_window_size=2097152");
        request.addHeader("X-H2-WINDOW", "12517377");
        request.addHeader("X-H2-PRIORITY", "");
        request.addHeader("X-JA3", "ios-safari-ja3");
        request.addHeader("X-JA4", "ios-safari-ja4");

        Map<String, Object> result = service.classify(request);

        assertThat(result.get("type")).isEqualTo("browser");
        assertThat(result.get("confidence")).isEqualTo("high");
    }
}
