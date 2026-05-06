package cn.gydev.challenge.controller;

import cn.gydev.challenge.service.gydev.GydevEvaluationPayload;
import cn.gydev.challenge.service.gydev.GydevEvaluationResult;
import cn.gydev.challenge.service.gydev.GydevGuardService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Gydev 防护演示接口，统一处理 GET/POST 提交流程。
 */
@RestController
@RequestMapping("/api/gydev")
public class GydevGuardController {

    private final GydevGuardService gydevGuardService;

    public GydevGuardController(GydevGuardService gydevGuardService) {
        this.gydevGuardService = gydevGuardService;
    }

    /**
     * 初始化挑战参数，供前端生成 token。
     *
     * @return 挑战参数
     */
    @GetMapping("/challenge/init")
    public Map<String, Object> initChallenge() {
        return gydevGuardService.initChallenge();
    }

    /**
     * 受 Gydev 防护模块保护的 GET 提交接口。
     *
     * @param content 业务内容
     * @param gydevToken Header 中的 Gydev-Token
     * @param sentinelProofToken Header 中的 Gydev-Sentinel-Proof-Token
     * @param request 当前请求
     * @return 统一评估结果
     */
    @GetMapping("/submit-get")
    public Map<String, Object> submitGet(
            @RequestParam("content") String content,
            @RequestHeader("Gydev-Token") String gydevToken,
            @RequestHeader("Gydev-Sentinel-Proof-Token") String sentinelProofToken,
            HttpServletRequest request) {
        GydevEvaluationPayload payload = new GydevEvaluationPayload();
        payload.setContent(content);
        payload.setGydevToken(gydevToken);
        payload.setGydevSentinelProofToken(sentinelProofToken);
        GydevEvaluationResult result = gydevGuardService.evaluate(request, payload);
        return result.toClientMap();
    }

    /**
     * 受 Gydev 防护模块保护的 POST 提交接口。
     *
     * @param body 请求体
     * @param gydevToken Header 中的 Gydev-Token
     * @param sentinelProofHeader Header 中的 Gydev-Sentinel-Proof-Token
     * @param request 当前请求
     * @return 带传输方式标记的统一评估结果
     */
    @PostMapping("/submit-post")
    public Map<String, Object> submitPost(
            @RequestBody Map<String, Object> body,
            @RequestHeader("Gydev-Token") String gydevToken,
            @RequestHeader("Gydev-Sentinel-Proof-Token") String sentinelProofHeader,
            HttpServletRequest request) {
        GydevEvaluationPayload payload = new GydevEvaluationPayload();
        payload.setContent(String.valueOf(body.getOrDefault("content", "")));
        payload.setGydevToken(gydevToken);
        payload.setGydevSentinelProofToken(sentinelProofHeader);
        GydevEvaluationResult result = gydevGuardService.evaluate(request, payload);
        return result.toClientMap();
    }
}
