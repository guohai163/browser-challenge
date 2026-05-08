package cn.gydev.challenge.service.gydev;

/**
 * Gydev 防护能力开关配置。
 * <p>
 * 所有能力默认开启；关闭后由上层模块按“跳过校验、不阻断请求”的策略处理。
 */
public class GydevGuardConfig {

    /**
     * 是否启用 TLS 指纹能力。
     */
    private boolean enableTlsFingerprint = true;
    /**
     * 是否启用 H2 指纹能力。
     */
    private boolean enableH2Fingerprint = true;
    /**
     * 是否启用 Gydev-Token 校验能力。
     */
    private boolean enableGydevToken = true;
    /**
     * 是否启用 Gydev-Sentinel-Proof-Token（PoW）校验能力。
     */
    private boolean enableSentinelProofToken = true;
    private boolean strictConsistency = true;
    private boolean requireSecChUaForChrome = true;
    private int maxAttemptsPerChallenge = 3;
    private long challengeTtlMs = 90_000L;
    private long tokenMaxAgeMs = 90_000L;
    private long powMaxAgeMs = 45_000L;
    private int powBaseDifficulty = 4;
    private int powRiskStep = 1;
    private int powMaxDifficulty = 7;

    /**
     * 获取 TLS 指纹开关。
     *
     * @return true 表示启用
     */
    public boolean isEnableTlsFingerprint() {
        return enableTlsFingerprint;
    }

    /**
     * 设置 TLS 指纹开关。
     *
     * @param enableTlsFingerprint true 启用，false 关闭
     */
    public void setEnableTlsFingerprint(boolean enableTlsFingerprint) {
        this.enableTlsFingerprint = enableTlsFingerprint;
    }

    /**
     * 获取 H2 指纹开关。
     *
     * @return true 表示启用
     */
    public boolean isEnableH2Fingerprint() {
        return enableH2Fingerprint;
    }

    /**
     * 设置 H2 指纹开关。
     *
     * @param enableH2Fingerprint true 启用，false 关闭
     */
    public void setEnableH2Fingerprint(boolean enableH2Fingerprint) {
        this.enableH2Fingerprint = enableH2Fingerprint;
    }

    /**
     * 获取 Gydev-Token 校验开关。
     *
     * @return true 表示启用
     */
    public boolean isEnableGydevToken() {
        return enableGydevToken;
    }

    /**
     * 设置 Gydev-Token 校验开关。
     *
     * @param enableGydevToken true 启用，false 关闭
     */
    public void setEnableGydevToken(boolean enableGydevToken) {
        this.enableGydevToken = enableGydevToken;
    }

    /**
     * 获取 Sentinel Proof（PoW）校验开关。
     *
     * @return true 表示启用
     */
    public boolean isEnableSentinelProofToken() {
        return enableSentinelProofToken;
    }

    /**
     * 设置 Sentinel Proof（PoW）校验开关。
     *
     * @param enableSentinelProofToken true 启用，false 关闭
     */
    public void setEnableSentinelProofToken(boolean enableSentinelProofToken) {
        this.enableSentinelProofToken = enableSentinelProofToken;
    }

    public boolean isStrictConsistency() {
        return strictConsistency;
    }

    public void setStrictConsistency(boolean strictConsistency) {
        this.strictConsistency = strictConsistency;
    }

    public boolean isRequireSecChUaForChrome() {
        return requireSecChUaForChrome;
    }

    public void setRequireSecChUaForChrome(boolean requireSecChUaForChrome) {
        this.requireSecChUaForChrome = requireSecChUaForChrome;
    }

    public int getMaxAttemptsPerChallenge() {
        return maxAttemptsPerChallenge;
    }

    public void setMaxAttemptsPerChallenge(int maxAttemptsPerChallenge) {
        this.maxAttemptsPerChallenge = maxAttemptsPerChallenge;
    }

    public long getChallengeTtlMs() {
        return challengeTtlMs;
    }

    public void setChallengeTtlMs(long challengeTtlMs) {
        this.challengeTtlMs = challengeTtlMs;
    }

    public long getTokenMaxAgeMs() {
        return tokenMaxAgeMs;
    }

    public void setTokenMaxAgeMs(long tokenMaxAgeMs) {
        this.tokenMaxAgeMs = tokenMaxAgeMs;
    }

    public long getPowMaxAgeMs() {
        return powMaxAgeMs;
    }

    public void setPowMaxAgeMs(long powMaxAgeMs) {
        this.powMaxAgeMs = powMaxAgeMs;
    }

    public int getPowBaseDifficulty() {
        return powBaseDifficulty;
    }

    public void setPowBaseDifficulty(int powBaseDifficulty) {
        this.powBaseDifficulty = powBaseDifficulty;
    }

    public int getPowRiskStep() {
        return powRiskStep;
    }

    public void setPowRiskStep(int powRiskStep) {
        this.powRiskStep = powRiskStep;
    }

    public int getPowMaxDifficulty() {
        return powMaxDifficulty;
    }

    public void setPowMaxDifficulty(int powMaxDifficulty) {
        this.powMaxDifficulty = powMaxDifficulty;
    }
}
