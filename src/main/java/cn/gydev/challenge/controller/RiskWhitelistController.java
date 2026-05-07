package cn.gydev.challenge.controller;

import cn.gydev.challenge.service.RiskFingerprintWhitelistRepository;
import cn.gydev.challenge.service.RiskSignalGateService;
import cn.gydev.challenge.service.TlsClassifierService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Browser whitelist capture/test APIs backed by DB.
 */
@RestController
@RequestMapping("/api/gydev/whitelist")
public class RiskWhitelistController {

    private final TlsClassifierService tlsClassifierService;
    private final RiskSignalGateService riskSignalGateService;

    public RiskWhitelistController(TlsClassifierService tlsClassifierService, RiskSignalGateService riskSignalGateService) {
        this.tlsClassifierService = tlsClassifierService;
        this.riskSignalGateService = riskSignalGateService;
    }

    /**
     * Capture current real browser fingerprint and store it to DB whitelist.
     */
    @PostMapping("/capture")
    public Map<String, Object> capture(HttpServletRequest request) {
        @SuppressWarnings("unchecked")
        Map<String, Object> tls = (Map<String, Object>) tlsClassifierService.classify(request);
        return riskSignalGateService.captureCurrentRequestToWhitelist(request, tls);
    }

    /**
     * Test current request against strong-signal gate.
     */
    @GetMapping("/test")
    public Map<String, Object> test(HttpServletRequest request) {
        @SuppressWarnings("unchecked")
        Map<String, Object> tls = (Map<String, Object>) tlsClassifierService.classify(request);
        Map<String, Object> gate = riskSignalGateService.verifyCurrentRequest(request, tls);
        Map<String, Object> out = new HashMap<>();
        out.put("gate", gate);
        out.put("tls", tls);
        return out;
    }

    /**
     * List enabled whitelist records from DB.
     */
    @GetMapping("/list")
    public List<RiskFingerprintWhitelistRepository.Record> list() {
        return riskSignalGateService.listWhitelist();
    }
}
