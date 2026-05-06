package cn.gydev.challenge.service.gydev;

/**
 * Feature toggles for Gydev guard capabilities.
 */
public class GydevGuardConfig {

    private boolean enableTlsFingerprint = true;
    private boolean enableH2Fingerprint = true;
    private boolean enableGydevToken = true;
    private boolean enableSentinelProofToken = true;

    public boolean isEnableTlsFingerprint() {
        return enableTlsFingerprint;
    }

    public void setEnableTlsFingerprint(boolean enableTlsFingerprint) {
        this.enableTlsFingerprint = enableTlsFingerprint;
    }

    public boolean isEnableH2Fingerprint() {
        return enableH2Fingerprint;
    }

    public void setEnableH2Fingerprint(boolean enableH2Fingerprint) {
        this.enableH2Fingerprint = enableH2Fingerprint;
    }

    public boolean isEnableGydevToken() {
        return enableGydevToken;
    }

    public void setEnableGydevToken(boolean enableGydevToken) {
        this.enableGydevToken = enableGydevToken;
    }

    public boolean isEnableSentinelProofToken() {
        return enableSentinelProofToken;
    }

    public void setEnableSentinelProofToken(boolean enableSentinelProofToken) {
        this.enableSentinelProofToken = enableSentinelProofToken;
    }
}

