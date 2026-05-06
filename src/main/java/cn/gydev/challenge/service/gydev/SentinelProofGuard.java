package cn.gydev.challenge.service.gydev;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Sentinel Proof 模块的开关与元信息封装。
 */
@Component
public class SentinelProofGuard {

    /**
     * 返回模块状态元信息，供统一响应聚合使用。
     *
     * @param enabled 是否启用 Sentinel Proof 模块
     * @return 模块状态信息
     */
    public Map<String, Object> status(boolean enabled) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("enabled", enabled);
        out.put("skipped", !enabled);
        out.put("tokenName", "Gydev-Sentinel-Proof-Token");
        return out;
    }
}
