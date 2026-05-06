package cn.gydev.challenge.controller;

import cn.gydev.challenge.service.TlsClassifierService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint for classifying caller type by TLS-related/request-level signals.
 */
@RestController
@RequestMapping("/api")
public class TlsController {

    private final TlsClassifierService tlsClassifierService;

    public TlsController(TlsClassifierService tlsClassifierService) {
        this.tlsClassifierService = tlsClassifierService;
    }

    /**
     * Classifies incoming requests as browser/program/unknown.
     *
     * @param request incoming request
     * @return classification payload
     */
    @GetMapping("/tls")
    public Map<String, Object> tls(HttpServletRequest request) {
        return tlsClassifierService.classify(request);
    }
}
