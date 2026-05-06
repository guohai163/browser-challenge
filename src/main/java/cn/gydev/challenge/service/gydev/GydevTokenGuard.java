package cn.gydev.challenge.service.gydev;

import cn.gydev.challenge.service.RiskChallengeService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Gydev Token 校验模块。
 */
@Component
public class GydevTokenGuard {

    private final RiskChallengeService riskChallengeService;

    public GydevTokenGuard(RiskChallengeService riskChallengeService) {
        this.riskChallengeService = riskChallengeService;
    }

    /**
     * 委托核心挑战服务初始化挑战数据。
     *
     * @return 挑战载荷
     */
    public Map<String, Object> initChallenge() {
        return riskChallengeService.initChallenge();
    }

    /**
     * 根据运行时开关执行 Gydev Token 与可选 Sentinel Proof 校验。
     *
     * @param request 当前请求
     * @param content 业务内容
     * @param gydevToken Gydev Token 值
     * @param sentinelProofToken Sentinel Proof Token 值
     * @param enableGydevToken 是否启用 Gydev Token 校验
     * @param enableSentinelProofToken 是否启用 Sentinel Proof 校验
     * @return 模块评估结果
     */
    public Map<String, Object> evaluate(
            HttpServletRequest request,
            String content,
            String gydevToken,
            String sentinelProofToken,
            boolean enableGydevToken,
            boolean enableSentinelProofToken) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (!enableGydevToken) {
            out.put("enabled", false);
            out.put("skipped", true);
            out.put("reason", "gydev_token_disabled");
            return out;
        }

        // PoW 关闭时切换到仅 Token 校验路径。
        Map<String, Object> result = enableSentinelProofToken
                ? riskChallengeService.validateSubmission(content, gydevToken, sentinelProofToken, request)
                : riskChallengeService.validateSubmissionWithoutPow(content, gydevToken, request);
        if (!enableSentinelProofToken && Boolean.TRUE.equals(result.get("accepted"))) {
            result.put("reason", "pow_skipped_by_config");
        }

        out.put("enabled", true);
        out.put("skipped", false);
        out.put("result", result);
        return out;
    }
}
