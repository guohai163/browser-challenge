package cn.gydev.challenge.service.gydev;

import cn.gydev.challenge.service.TlsClassifierService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * TLS/H2 指纹评估模块。
 */
@Component
public class TlsFingerprintGuard {

    private final TlsClassifierService tlsClassifierService;

    public TlsFingerprintGuard(TlsClassifierService tlsClassifierService) {
        this.tlsClassifierService = tlsClassifierService;
    }

    /**
     * 执行 TLS/H2 指纹评估，并按开关对结果做特征屏蔽。
     *
     * @param request 当前请求
     * @param enableTls 是否启用 TLS 指纹信号
     * @param enableH2 是否启用 H2 指纹信号
     * @return 模块评估结果
     */
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
