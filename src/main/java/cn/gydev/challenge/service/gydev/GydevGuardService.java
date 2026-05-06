package cn.gydev.challenge.service.gydev;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * Unified orchestrator for gydev anti-bot capabilities with runtime toggles.
 */
@Service
public class GydevGuardService {

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

    public Map<String, Object> initChallenge() {
        Map<String, Object> challenge = gydevTokenGuard.initChallenge();
        challenge.put("guardConfig", Map.of(
                "enableTlsFingerprint", config.isEnableTlsFingerprint(),
                "enableH2Fingerprint", config.isEnableH2Fingerprint(),
                "enableGydevToken", config.isEnableGydevToken(),
                "enableSentinelProofToken", config.isEnableSentinelProofToken()
        ));
        return challenge;
    }

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
        return out;
    }
}

