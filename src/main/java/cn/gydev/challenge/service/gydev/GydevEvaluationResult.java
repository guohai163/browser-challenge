package cn.gydev.challenge.service.gydev;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Gydev 防护服务的标准化评估结果。
 */
public class GydevEvaluationResult {

    private boolean accepted;
    private String riskLevel;
    private String reason;
    private boolean powVerified;
    private final Map<String, Object> modules = new LinkedHashMap<>();
    private final Map<String, Object> details = new LinkedHashMap<>();

    public boolean isAccepted() {
        return accepted;
    }

    public void setAccepted(boolean accepted) {
        this.accepted = accepted;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public boolean isPowVerified() {
        return powVerified;
    }

    public void setPowVerified(boolean powVerified) {
        this.powVerified = powVerified;
    }

    public Map<String, Object> getModules() {
        return modules;
    }

    public Map<String, Object> getDetails() {
        return details;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("accepted", accepted);
        out.put("riskLevel", riskLevel);
        out.put("reason", reason);
        out.put("powVerified", powVerified);
        out.put("modules", modules);
        out.put("details", details);
        return out;
    }

    /**
     * 对前端暴露的最小化结果，仅包含是否拦截与风险等级。
     */
    public Map<String, Object> toClientMap() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("blocked", !accepted);
        out.put("riskLevel", riskLevel);
        return out;
    }
}
