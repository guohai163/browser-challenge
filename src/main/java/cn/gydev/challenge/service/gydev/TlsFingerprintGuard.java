package cn.gydev.challenge.service.gydev;

import cn.gydev.challenge.service.TlsClassifierService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Guard module for TLS/H2 fingerprint evaluation.
 */
@Component
public class TlsFingerprintGuard {

    private final TlsClassifierService tlsClassifierService;

    public TlsFingerprintGuard(TlsClassifierService tlsClassifierService) {
        this.tlsClassifierService = tlsClassifierService;
    }

    public Map<String, Object> evaluate(HttpServletRequest request, boolean enableTls, boolean enableH2) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (!enableTls && !enableH2) {
            out.put("enabled", false);
            out.put("skipped", true);
            out.put("reason", "tls_h2_disabled");
            return out;
        }

        Map<String, Object> raw = tlsClassifierService.classify(request);
        if (!enableH2) {
            @SuppressWarnings("unchecked")
            Map<String, Object> fingerprints = (Map<String, Object>) raw.get("fingerprints");
            fingerprints.put("h2", "");
        }

        out.put("enabled", true);
        out.put("skipped", false);
        out.put("raw", raw);
        return out;
    }
}

