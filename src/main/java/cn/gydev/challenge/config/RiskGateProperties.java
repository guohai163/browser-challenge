package cn.gydev.challenge.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Strong gate configuration for fingerprint trust, whitelist and circuit breaker.
 */
@Component
@ConfigurationProperties(prefix = "risk.gate")
public class RiskGateProperties {

    private boolean enabled = true;
    private List<String> trustedProxyIps = new ArrayList<>();
    private List<FingerprintWhitelistEntry> whitelist = new ArrayList<>();
    private CircuitBreaker circuit = new CircuitBreaker();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getTrustedProxyIps() {
        return trustedProxyIps;
    }

    public void setTrustedProxyIps(List<String> trustedProxyIps) {
        this.trustedProxyIps = trustedProxyIps;
    }

    public List<FingerprintWhitelistEntry> getWhitelist() {
        return whitelist;
    }

    public void setWhitelist(List<FingerprintWhitelistEntry> whitelist) {
        this.whitelist = whitelist;
    }

    public CircuitBreaker getCircuit() {
        return circuit;
    }

    public void setCircuit(CircuitBreaker circuit) {
        this.circuit = circuit;
    }

    public static class FingerprintWhitelistEntry {
        private boolean enabled = true;
        private String browserFamily = "";
        private int majorVersion;
        private String ja3 = "";
        private String ja4 = "";
        private String h2 = "";
        private String updatedAt = "";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getBrowserFamily() {
            return browserFamily;
        }

        public void setBrowserFamily(String browserFamily) {
            this.browserFamily = browserFamily;
        }

        public int getMajorVersion() {
            return majorVersion;
        }

        public void setMajorVersion(int majorVersion) {
            this.majorVersion = majorVersion;
        }

        public String getJa3() {
            return ja3;
        }

        public void setJa3(String ja3) {
            this.ja3 = ja3;
        }

        public String getJa4() {
            return ja4;
        }

        public void setJa4(String ja4) {
            this.ja4 = ja4;
        }

        public String getH2() {
            return h2;
        }

        public void setH2(String h2) {
            this.h2 = h2;
        }

        public String getUpdatedAt() {
            return updatedAt;
        }

        public void setUpdatedAt(String updatedAt) {
            this.updatedAt = updatedAt;
        }
    }

    public static class CircuitBreaker {
        private int lightThreshold = 15;
        private int mediumThreshold = 30;
        private int heavyThreshold = 60;
        private long windowMs = 60_000L;
        private long lightBlockMs = 30_000L;
        private long mediumBlockMs = 180_000L;
        private long heavyBlockMs = 600_000L;

        public int getLightThreshold() {
            return lightThreshold;
        }

        public void setLightThreshold(int lightThreshold) {
            this.lightThreshold = lightThreshold;
        }

        public int getMediumThreshold() {
            return mediumThreshold;
        }

        public void setMediumThreshold(int mediumThreshold) {
            this.mediumThreshold = mediumThreshold;
        }

        public int getHeavyThreshold() {
            return heavyThreshold;
        }

        public void setHeavyThreshold(int heavyThreshold) {
            this.heavyThreshold = heavyThreshold;
        }

        public long getWindowMs() {
            return windowMs;
        }

        public void setWindowMs(long windowMs) {
            this.windowMs = windowMs;
        }

        public long getLightBlockMs() {
            return lightBlockMs;
        }

        public void setLightBlockMs(long lightBlockMs) {
            this.lightBlockMs = lightBlockMs;
        }

        public long getMediumBlockMs() {
            return mediumBlockMs;
        }

        public void setMediumBlockMs(long mediumBlockMs) {
            this.mediumBlockMs = mediumBlockMs;
        }

        public long getHeavyBlockMs() {
            return heavyBlockMs;
        }

        public void setHeavyBlockMs(long heavyBlockMs) {
            this.heavyBlockMs = heavyBlockMs;
        }
    }
}
