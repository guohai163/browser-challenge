package cn.gydev.challenge.service.gydev;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Gydev 防护能力统一编排服务，支持按开关启停模块。
 */
@Service
public class GydevGuardService {
    private static final Logger log = LoggerFactory.getLogger(GydevGuardService.class);

    private final GydevGuardConfig config;
    private final TlsFingerprintGuard tlsFingerprintGuard;
    private final GydevTokenGuard gydevTokenGuard;
    private final SentinelProofGuard sentinelProofGuard;

    public GydevGuardService(
            GydevGuardConfig config,
            TlsFingerprintGuard tlsFingerprintGuard,
            GydevTokenGuard gydevTokenGuard,
            SentinelProofGuard sentinelProofGuard) {
        this.config = config;
        this.tlsFingerprintGuard = tlsFingerprintGuard;
        this.gydevTokenGuard = gydevTokenGuard;
        this.sentinelProofGuard = sentinelProofGuard;
    }

    /**
     * 初始化挑战数据，并返回当前启用的防护开关快照。
     *
     * @return 含防护开关信息的挑战载荷
     */
    public Map<String, Object> initChallenge() {
        // 先从核心挑战服务生成基础挑战数据（challengeId、salt、pow 参数等）。
        Map<String, Object> challenge = gydevTokenGuard.initChallenge();
        // 将当前后端防护开关快照附加到返回值，便于前端按能力动态处理流程。
        challenge.put("guardConfig", Map.of(
                "enableTlsFingerprint", config.isEnableTlsFingerprint(),
                "enableH2Fingerprint", config.isEnableH2Fingerprint(),
                "enableGydevToken", config.isEnableGydevToken(),
                "enableSentinelProofToken", config.isEnableSentinelProofToken()
        ));
        // 返回带 guardConfig 的挑战载荷。
        return challenge;
    }

    /**
     * 执行所有已启用模块并聚合为统一判定结果。
     *
     * @param request 当前请求
     * @param payload 提交载荷
     * @return 统一评估结果
     */
    public GydevEvaluationResult evaluate(HttpServletRequest request, GydevEvaluationPayload payload) {
        GydevEvaluationResult out = new GydevEvaluationResult();

        Map<String, Object> tls = tlsFingerprintGuard.evaluate(
                request,
                config.isEnableTlsFingerprint(),
                config.isEnableH2Fingerprint()
        );
        Map<String, Object> sentinelMeta = sentinelProofGuard.status(config.isEnableSentinelProofToken());
        Map<String, Object> gydevToken = gydevTokenGuard.evaluate(
                request,
                payload.getContent(),
                payload.getGydevToken(),
                payload.getGydevSentinelProofToken(),
                config.isEnableGydevToken(),
                config.isEnableSentinelProofToken()
        );

        out.getModules().put("tlsFingerprint", tls);
        out.getModules().put("sentinelProof", sentinelMeta);
        out.getModules().put("gydevToken", gydevToken);

        @SuppressWarnings("unchecked")
        Map<String, Object> gydevResult = (Map<String, Object>) gydevToken.get("result");
        if (gydevResult == null) {
            // Token 模块关闭时，采用放行策略并标注跳过原因。
            out.setAccepted(true);
            out.setRiskLevel("low");
            out.setReason("gydev_token_skipped");
            out.setPowVerified(!config.isEnableSentinelProofToken());
            return out;
        }

        out.setAccepted(Boolean.TRUE.equals(gydevResult.get("accepted")));
        out.setRiskLevel(String.valueOf(gydevResult.getOrDefault("riskLevel", "low")));
        out.setReason(String.valueOf(gydevResult.getOrDefault("reason", "")));
        out.setPowVerified(Boolean.TRUE.equals(gydevResult.get("powVerified")));
        out.getDetails().putAll(gydevResult);
        log.info(
                "gydev-eval decision: blocked={}, riskLevel={}, reason={}, powVerified={}, modules={}",
                !out.isAccepted(),
                out.getRiskLevel(),
                out.getReason(),
                out.isPowVerified(),
                out.getModules()
        );
        return out;
    }
}
