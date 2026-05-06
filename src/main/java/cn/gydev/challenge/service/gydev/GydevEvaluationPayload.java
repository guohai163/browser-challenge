package cn.gydev.challenge.service.gydev;

/**
 * Gydev 防护评估输入载荷。
 */
public class GydevEvaluationPayload {

    private String content;
    private String gydevToken;
    private String gydevSentinelProofToken;

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getGydevToken() {
        return gydevToken;
    }

    public void setGydevToken(String gydevToken) {
        this.gydevToken = gydevToken;
    }

    public String getGydevSentinelProofToken() {
        return gydevSentinelProofToken;
    }

    public void setGydevSentinelProofToken(String gydevSentinelProofToken) {
        this.gydevSentinelProofToken = gydevSentinelProofToken;
    }
}
