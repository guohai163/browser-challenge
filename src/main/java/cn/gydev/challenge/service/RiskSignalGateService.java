package cn.gydev.challenge.service;

import cn.gydev.challenge.config.RiskGateProperties;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Strong-signal gate: trusted source + required fingerprints + whitelist + circuit breaker.
 */
@Service
public class RiskSignalGateService {
    private static final Logger log = LoggerFactory.getLogger(RiskSignalGateService.class);

    private final RiskGateProperties properties;
    private final RiskFingerprintWhitelistRepository whitelistRepository;
    private final ConcurrentMap<String, CounterState> counters = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Long> blockedUntil = new ConcurrentHashMap<>();

    public RiskSignalGateService(RiskGateProperties properties, RiskFingerprintWhitelistRepository whitelistRepository) {
        this.properties = properties;
        this.whitelistRepository = whitelistRepository;
    }

    public Map<String, Object> verify(HttpServletRequest request, Map<String, Object> tlsClassifierResult) {
        List<String> failures = new ArrayList<>();
        if (!properties.isEnabled()) {
            return gateResult(true, failures, "none");
        }

        String sourceIp = remoteIp(request);
        String ja3 = readFingerprint(tlsClassifierResult, "ja3");
        String ja4 = readFingerprint(tlsClassifierResult, "ja4");
        String h2 = readFingerprint(tlsClassifierResult, "h2");

        if (isBlocked(sourceIp, ja3)) {
            failures.add("circuit_blocked");
            return gateResult(false, failures, "heavy");
        }

        if (!isValidFingerprintValue(ja3) || !isValidFingerprintValue(ja4) || !isValidFingerprintValue(h2)) {
            failures.add("missing_tls_fingerprint");
        }

        BrowserIdentity identity = parseBrowserIdentity(header(request, "User-Agent"));
        if (!isWhitelisted(identity, ja3, ja4, h2)) {
            failures.add("fingerprint_not_whitelisted");
        }

        if (!failures.isEmpty()) {
            String level = trackAndMaybeBlock(sourceIp, ja3, failures);
            return gateResult(false, failures, level);
        }

        return gateResult(true, failures, "none");
    }

    public Map<String, Object> verifyCurrentRequest(HttpServletRequest request, Map<String, Object> tlsClassifierResult) {
        return verify(request, tlsClassifierResult);
    }

    public Map<String, Object> captureCurrentRequestToWhitelist(HttpServletRequest request, Map<String, Object> tlsClassifierResult) {
        String ja3 = readFingerprint(tlsClassifierResult, "ja3");
        String ja4 = readFingerprint(tlsClassifierResult, "ja4");
        String h2 = readFingerprint(tlsClassifierResult, "h2");
        BrowserIdentity identity = parseBrowserIdentity(header(request, "User-Agent"));

        List<String> failures = new ArrayList<>();
        if (!isValidFingerprintValue(ja3) || !isValidFingerprintValue(ja4) || !isValidFingerprintValue(h2)) {
            failures.add("missing_tls_fingerprint");
        }
        if ("unknown".equals(identity.family()) || identity.majorVersion() <= 0) {
            failures.add("unknown_browser_identity");
        }

        Map<String, Object> out = new HashMap<>();
        out.put("captured", failures.isEmpty());
        out.put("failures", failures);
        out.put("browserFamily", identity.family());
        out.put("majorVersion", identity.majorVersion());
        out.put("ja3", ja3);
        out.put("ja4", ja4);
        out.put("h2", h2);
        if (!failures.isEmpty()) {
            return out;
        }

        whitelistRepository.upsert(identity.family(), identity.majorVersion(), ja3, ja4, h2, "browser_capture");
        out.put("whitelisted", true);
        return out;
    }

    public List<RiskFingerprintWhitelistRepository.Record> listWhitelist() {
        return whitelistRepository.listEnabled();
    }

    private Map<String, Object> gateResult(boolean passed, List<String> failures, String circuitLevel) {
        Map<String, Object> out = new HashMap<>();
        out.put("gatePassed", passed);
        out.put("gateFailures", failures);
        out.put("circuitLevel", circuitLevel);
        return out;
    }

    private boolean isBlocked(String sourceIp, String ja3) {
        long now = System.currentTimeMillis();
        Long ipUntil = blockedUntil.get("ip:" + sourceIp);
        Long fpUntil = blockedUntil.get("ja3:" + ja3);
        return (ipUntil != null && ipUntil > now) || (fpUntil != null && fpUntil > now);
    }

    private String trackAndMaybeBlock(String sourceIp, String ja3, List<String> failures) {
        Set<String> tracked = new HashSet<>(failures);
        tracked.retainAll(Set.of("pow_invalid", "pow_replay", "fingerprint_not_whitelisted"));
        if (tracked.isEmpty()) {
            return "none";
        }

        long now = System.currentTimeMillis();
        String key = sourceIp + "|" + (ja3 == null ? "" : ja3);
        CounterState state = counters.computeIfAbsent(key, k -> new CounterState(now, new AtomicInteger(0)));
        synchronized (state) {
            long windowMs = properties.getCircuit().getWindowMs();
            if (now - state.windowStartMs > windowMs) {
                state.windowStartMs = now;
                state.count.set(0);
            }
            int total = state.count.incrementAndGet();
            int heavy = properties.getCircuit().getHeavyThreshold();
            int medium = properties.getCircuit().getMediumThreshold();
            int light = properties.getCircuit().getLightThreshold();
            if (total >= heavy) {
                applyBlock(sourceIp, ja3, properties.getCircuit().getHeavyBlockMs());
                log.warn("risk_circuit_breaker_trigger_total level=heavy key={} failures={}", key, tracked);
                return "heavy";
            }
            if (total >= medium) {
                applyBlock(sourceIp, ja3, properties.getCircuit().getMediumBlockMs());
                log.warn("risk_circuit_breaker_trigger_total level=medium key={} failures={}", key, tracked);
                return "medium";
            }
            if (total >= light) {
                applyBlock(sourceIp, ja3, properties.getCircuit().getLightBlockMs());
                log.warn("risk_circuit_breaker_trigger_total level=light key={} failures={}", key, tracked);
                return "light";
            }
        }
        return "none";
    }

    private void applyBlock(String sourceIp, String ja3, long blockMs) {
        long until = System.currentTimeMillis() + Math.max(0L, blockMs);
        blockedUntil.put("ip:" + sourceIp, until);
        if (ja3 != null && !ja3.isBlank()) {
            blockedUntil.put("ja3:" + ja3, until);
        }
    }

    private boolean isWhitelisted(BrowserIdentity identity, String ja3, String ja4, String h2) {
        if (identity == null || identity.majorVersion() <= 0 || identity.family() == null || identity.family().isBlank()) {
            return false;
        }
        return whitelistRepository.isWhitelisted(
                identity.family().toLowerCase(Locale.ROOT),
                identity.majorVersion(),
                normalized(ja3),
                normalized(ja4),
                normalized(h2)
        );
    }

    private BrowserIdentity parseBrowserIdentity(String userAgent) {
        if (userAgent == null) {
            return new BrowserIdentity("unknown", 0);
        }
        String ua = userAgent.toLowerCase(Locale.ROOT);
        if (ua.contains("edg/")) {
            return new BrowserIdentity("edge", majorVersion(ua, "edg/"));
        }
        if (ua.contains("chrome/")) {
            return new BrowserIdentity("chrome", majorVersion(ua, "chrome/"));
        }
        if (ua.contains("safari/") && ua.contains("version/")) {
            return new BrowserIdentity("safari", majorVersion(ua, "version/"));
        }
        if (ua.contains("firefox/")) {
            return new BrowserIdentity("firefox", majorVersion(ua, "firefox/"));
        }
        return new BrowserIdentity("unknown", 0);
    }

    private int majorVersion(String ua, String token) {
        int idx = ua.indexOf(token);
        if (idx < 0) {
            return 0;
        }
        int start = idx + token.length();
        int end = start;
        while (end < ua.length() && Character.isDigit(ua.charAt(end))) {
            end++;
        }
        if (end <= start) {
            return 0;
        }
        try {
            return Integer.parseInt(ua.substring(start, end));
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    @SuppressWarnings("unchecked")
    private String readFingerprint(Map<String, Object> tlsClassifierResult, String key) {
        if (tlsClassifierResult == null) {
            return "";
        }
        Object fps = tlsClassifierResult.get("fingerprints");
        if (!(fps instanceof Map<?, ?> map)) {
            return "";
        }
        Object raw = ((Map<String, Object>) map).get(key);
        return raw == null ? "" : String.valueOf(raw).trim();
    }

    private boolean isValidFingerprintValue(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String lower = value.trim().toLowerCase(Locale.ROOT);
        return !("unknown".equals(lower) || "n/a".equals(lower) || "null".equals(lower) || "-".equals(lower));
    }

    private String normalized(String value) {
        return value == null ? "" : value.trim();
    }

    private String remoteIp(HttpServletRequest request) {
        String direct = request.getRemoteAddr();
        if (direct != null && !direct.isBlank()) {
            return direct.trim();
        }
        return "unknown";
    }

    private String header(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return value == null ? "" : value.trim();
    }

    private record BrowserIdentity(String family, int majorVersion) {
    }

    private static final class CounterState {
        private long windowStartMs;
        private final AtomicInteger count;

        private CounterState(long windowStartMs, AtomicInteger count) {
            this.windowStartMs = windowStartMs;
            this.count = count;
        }
    }
}
