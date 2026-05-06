package cn.gydev.challenge.config;

import cn.gydev.challenge.service.gydev.GydevGuardConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Gydev 防护开关的 Spring Bean 配置。
 */
@Configuration
public class GydevGuardConfiguration {

    /**
     * 创建 Gydev 防护模块的默认运行时开关配置。
     *
     * @return Gydev 防护配置 Bean
     */
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
