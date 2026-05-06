package cn.gydev.challenge.service;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * 基于请求可见信号与可选 TLS 指纹头对调用方类型进行分类。
 * <p>
 * 注意：Spring Boot 在 TLS 终止之后无法直接读取 ClientHello 字段，
 * 若需更强 TLS 判别能力，应由网关/代理透传 JA3/JA4 等指纹。
 */
@Service
public class TlsClassifierService {
    private static final int H2_WEIGHT = 50;
    private static final int TLS_WEIGHT = 35;
    private static final int HEADER_WEIGHT = 15;

    private static final String TYPE_BROWSER = "browser";
    private static final String TYPE_PROGRAM = "program";
    private static final String TYPE_UNKNOWN = "unknown";

    /**
     * 将请求分类为浏览器请求或程序化请求。
     *
     * @param request 当前 HTTP 请求
     * @return 分类详情
     */
    public Map<String, Object> classify(HttpServletRequest request) {
        String userAgent = header(request, "User-Agent");
        String secChUa = header(request, "Sec-CH-UA");
        String secFetchSite = header(request, "Sec-Fetch-Site");
        String acceptLanguage = header(request, "Accept-Language");

        // 可选指纹头，通常由反向代理/WAF 注入。
        String ja3 = firstNonBlank(
                header(request, "X-JA3"),
                header(request, "JA3"),
                header(request, "X-TLS-JA3"));
        String ja4 = firstNonBlank(
                header(request, "X-JA4"),
                header(request, "JA4"),
                header(request, "X-TLS-JA4"));
        String h2Fp = firstNonBlank(
                header(request, "X-H2-FP"),
                header(request, "X-TLS-H2-FP"));
        String h2Settings = header(request, "X-H2-SETTINGS");
        String h2Window = header(request, "X-H2-WINDOW");
        String h2Priority = header(request, "X-H2-PRIORITY");

        boolean browserHeaderFamily = looksLikeBrowserByHeaders(userAgent, secChUa, secFetchSite, acceptLanguage);
        boolean programHeaderFamily = looksLikeProgram(userAgent, secChUa, secFetchSite, acceptLanguage);
        boolean browserLikeH2 = looksLikeBrowserH2(h2Fp, h2Settings, h2Window, h2Priority);
        boolean programLikeH2 = looksLikeProgramH2(h2Fp, h2Settings, h2Window, h2Priority);
        boolean hasH2Signal = hasH2Signal(h2Fp, h2Settings, h2Window, h2Priority);
        boolean hasTlsSignal = !ja3.isBlank() || !ja4.isBlank();

        int browserH2Score = browserLikeH2 ? H2_WEIGHT : 0;
        int programH2Score = programLikeH2 ? H2_WEIGHT : 0;
        int browserTlsScore = hasTlsSignal && browserHeaderFamily ? TLS_WEIGHT : 0;
        int programTlsScore = hasTlsSignal && !browserHeaderFamily ? TLS_WEIGHT : 0;
        int browserHeaderScore = browserHeaderFamily ? HEADER_WEIGHT : 0;
        int programHeaderScore = programHeaderFamily ? HEADER_WEIGHT : 0;

        int browserScore = browserH2Score + browserTlsScore + browserHeaderScore;
        int programScore = programH2Score + programTlsScore + programHeaderScore;

        String type = TYPE_UNKNOWN;
        String confidence = "low";
        String reason = "Insufficient signals";
        int delta = Math.abs(browserScore - programScore);

        if (browserScore == 0 && programScore == 0) {
            type = TYPE_UNKNOWN;
            confidence = "low";
            reason = "Insufficient signals";
        } else if (delta <= 10) {
            type = TYPE_UNKNOWN;
            confidence = "low";
            reason = "Conflicting signals across H2/TLS/header families";
        } else if (browserScore > programScore) {
            type = TYPE_BROWSER;
            confidence = hasH2Signal && hasTlsSignal ? "high" : "medium";
            reason = hasH2Signal
                    ? "Browser-leaning H2 fingerprint and header family signals"
                    : "Browser-style headers dominate; H2 fingerprint missing";
        } else {
            type = TYPE_PROGRAM;
            confidence = hasH2Signal && hasTlsSignal ? "high" : "medium";
            reason = hasH2Signal
                    ? "Program-leaning H2 fingerprint and header family signals"
                    : "Program-like header traits dominate; H2 fingerprint missing";
        }

        if (hasH2Signal && !hasTlsSignal && "high".equals(confidence)) {
            // 仅有 H2 而缺少 JA3/JA4 时，置信度上限降为 medium。
            confidence = "medium";
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("type", type);
        result.put("confidence", confidence);
        result.put("reason", reason);
        Map<String, Object> scoreBreakdown = new LinkedHashMap<>();
        scoreBreakdown.put("h2", Map.of("browser", browserH2Score, "program", programH2Score));
        scoreBreakdown.put("tls", Map.of("browser", browserTlsScore, "program", programTlsScore));
        scoreBreakdown.put("header", Map.of("browser", browserHeaderScore, "program", programHeaderScore));
        scoreBreakdown.put("total", Map.of("browser", browserScore, "program", programScore));
        result.put("scoreBreakdown", scoreBreakdown);
        result.put("fingerprints", Map.of("ja3", ja3, "ja4", ja4, "h2", h2Fp));

        Map<String, Object> h2Details = new HashMap<>();
        h2Details.put("settings", h2Settings);
        h2Details.put("window", h2Window);
        h2Details.put("priority", h2Priority);
        result.put("signals", Map.of(
                "userAgent", userAgent,
                "secChUa", secChUa,
                "secFetchSite", secFetchSite,
                "acceptLanguage", acceptLanguage,
                "h2Details", h2Details
        ));
        return result;
    }

    private boolean looksLikeBrowserByHeaders(String userAgent, String secChUa, String secFetchSite, String acceptLanguage) {
        String ua = userAgent.toLowerCase(Locale.ROOT);
        boolean uaBrowser = ua.contains("mozilla/5.0")
                || ua.contains("chrome/")
                || ua.contains("safari/")
                || ua.contains("firefox/")
                || ua.contains("edg/");
        boolean chUa = !secChUa.isBlank();
        boolean fetchHeaders = !secFetchSite.isBlank();
        boolean langHeader = !acceptLanguage.isBlank();
        return uaBrowser && (chUa || fetchHeaders || langHeader);
    }

    private boolean looksLikeProgram(String userAgent, String secChUa, String secFetchSite, String acceptLanguage) {
        String ua = userAgent.toLowerCase(Locale.ROOT);
        boolean programUa = ua.contains("python-requests")
                || ua.contains("python-urllib")
                || ua.contains("curl/")
                || ua.contains("wget/")
                || ua.contains("httpclient")
                || ua.contains("okhttp")
                || ua.contains("postmanruntime")
                || ua.contains("go-http-client")
                || ua.contains("java/")
                || ua.isBlank();
        boolean missingBrowserHints = secChUa.isBlank() && secFetchSite.isBlank() && acceptLanguage.isBlank();
        return programUa || missingBrowserHints;
    }

    private boolean hasH2Signal(String h2Fp, String h2Settings, String h2Window, String h2Priority) {
        return !h2Fp.isBlank() || !h2Settings.isBlank() || !h2Window.isBlank() || !h2Priority.isBlank();
    }

    private boolean looksLikeBrowserH2(String h2Fp, String h2Settings, String h2Window, String h2Priority) {
        String merged = (h2Fp + " " + h2Settings + " " + h2Window + " " + h2Priority).toLowerCase(Locale.ROOT);
        return merged.contains("chrome")
                || merged.contains("safari")
                || merged.contains("firefox")
                || merged.contains("edge")
                || merged.contains("browser");
    }

    private boolean looksLikeProgramH2(String h2Fp, String h2Settings, String h2Window, String h2Priority) {
        String merged = (h2Fp + " " + h2Settings + " " + h2Window + " " + h2Priority).toLowerCase(Locale.ROOT);
        return merged.contains("curl")
                || merged.contains("python")
                || merged.contains("httpclient")
                || merged.contains("okhttp")
                || merged.contains("program")
                || (hasH2Signal(h2Fp, h2Settings, h2Window, h2Priority) && !looksLikeBrowserH2(h2Fp, h2Settings, h2Window, h2Priority));
    }

    private String header(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return value == null ? "" : value.trim();
    }

    private String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v.trim();
            }
        }
        return "";
    }
}
