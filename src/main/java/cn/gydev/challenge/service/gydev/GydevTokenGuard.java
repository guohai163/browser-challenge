package cn.gydev.challenge.service.gydev;

import cn.gydev.challenge.service.RiskChallengeService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Guard module for gydev token validation.
 */
@Component
public class GydevTokenGuard {

    private final RiskChallengeService riskChallengeService;

    public GydevTokenGuard(RiskChallengeService riskChallengeService) {
        this.riskChallengeService = riskChallengeService;
    }

    public Map<String, Object> initChallenge() {
        return riskChallengeService.initChallenge();
    }

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
