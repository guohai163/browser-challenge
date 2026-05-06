package cn.gydev.challenge.service.gydev;

import static org.assertj.core.api.Assertions.assertThat;

import cn.gydev.challenge.service.RiskChallengeService;
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
                new GydevTokenGuard(new RiskChallengeService(tls)),
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
                new GydevTokenGuard(new RiskChallengeService(tls)),
                new SentinelProofGuard()
        );

        GydevEvaluationPayload payload = new GydevEvaluationPayload();
        payload.setContent("demo");
        payload.setGydevToken("");
        payload.setGydevSentinelProofToken("");
        GydevEvaluationResult result = service.evaluate(new MockHttpServletRequest(), payload);

        assertThat(result.isAccepted()).isFalse();
    }
}

