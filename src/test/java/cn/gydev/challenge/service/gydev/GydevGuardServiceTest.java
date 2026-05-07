package cn.gydev.challenge.service.gydev;

import static org.assertj.core.api.Assertions.assertThat;

import cn.gydev.challenge.service.RiskChallengeService;
import cn.gydev.challenge.service.RiskSignalGateService;
import cn.gydev.challenge.service.TlsClassifierService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class GydevGuardServiceTest {

    @Test
    void shouldSkipAllWhenFeaturesDisabled() {
        GydevGuardConfig config = new GydevGuardConfig();
        config.setEnableTlsFingerprint(false);
        config.setEnableH2Fingerprint(false);
        config.setEnableGydevToken(false);
        config.setEnableSentinelProofToken(false);

        TlsClassifierService tls = new TlsClassifierService();
        GydevGuardService service = new GydevGuardService(
                config,
                new TlsFingerprintGuard(tls),
                new GydevTokenGuard(new RiskChallengeService(tls, new StubRiskSignalGateService())),
                new SentinelProofGuard()
        );

        GydevEvaluationPayload payload = new GydevEvaluationPayload();
        payload.setContent("demo");
        payload.setGydevToken("unused");
        payload.setGydevSentinelProofToken("unused");
        GydevEvaluationResult result = service.evaluate(new MockHttpServletRequest(), payload);

        assertThat(result.isAccepted()).isTrue();
        assertThat(result.getModules()).containsKey("tlsFingerprint");
        assertThat(result.getModules()).containsKey("gydevToken");
    }

    @Test
    void shouldRejectWhenNewFieldsMissing() {
        GydevGuardConfig config = new GydevGuardConfig();
        TlsClassifierService tls = new TlsClassifierService();
        GydevGuardService service = new GydevGuardService(
                config,
                new TlsFingerprintGuard(tls),
                new GydevTokenGuard(new RiskChallengeService(tls, new StubRiskSignalGateService())),
                new SentinelProofGuard()
        );

        GydevEvaluationPayload payload = new GydevEvaluationPayload();
        payload.setContent("demo");
        payload.setGydevToken("");
        payload.setGydevSentinelProofToken("");
        GydevEvaluationResult result = service.evaluate(new MockHttpServletRequest(), payload);

        assertThat(result.isAccepted()).isFalse();
    }

    private static final class StubRiskSignalGateService extends RiskSignalGateService {
        private StubRiskSignalGateService() {
            super(new cn.gydev.challenge.config.RiskGateProperties(), null);
        }

        @Override
        public java.util.Map<String, Object> verify(jakarta.servlet.http.HttpServletRequest request, java.util.Map<String, Object> tlsClassifierResult) {
            java.util.Map<String, Object> out = new java.util.LinkedHashMap<>();
            out.put("gatePassed", true);
            out.put("gateFailures", java.util.List.of());
            out.put("circuitLevel", "none");
            return out;
        }
    }
}
