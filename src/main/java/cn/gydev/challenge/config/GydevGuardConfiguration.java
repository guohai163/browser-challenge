package cn.gydev.challenge.config;

import cn.gydev.challenge.service.gydev.GydevGuardConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring bean configuration for Gydev guard toggles.
 */
@Configuration
public class GydevGuardConfiguration {

    @Bean
    public GydevGuardConfig gydevGuardConfig() {
        GydevGuardConfig config = new GydevGuardConfig();
        config.setEnableTlsFingerprint(true);
        config.setEnableH2Fingerprint(true);
        config.setEnableGydevToken(true);
        config.setEnableSentinelProofToken(true);
        return config;
    }
}

