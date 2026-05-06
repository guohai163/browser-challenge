package cn.gydev.challenge.service.gydev;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Dedicated module-level toggle/metadata for sentinel proof capability.
 */
@Component
public class SentinelProofGuard {

    public Map<String, Object> status(boolean enabled) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", enabled);
        out.put("skipped", !enabled);
        out.put("tokenName", "Gydev-Sentinel-Proof-Token");
        return out;
    }
}

