package cn.gydev.challenge.controller;

import cn.gydev.challenge.service.gydev.GydevEvaluationPayload;
import cn.gydev.challenge.service.gydev.GydevEvaluationResult;
import cn.gydev.challenge.service.gydev.GydevGuardService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Unified gydev guard demo endpoints for GET and POST submission.
 */
@RestController
@RequestMapping("/api/gydev")
public class GydevGuardController {

    private final GydevGuardService gydevGuardService;

    public GydevGuardController(GydevGuardService gydevGuardService) {
        this.gydevGuardService = gydevGuardService;
    }

    @GetMapping("/challenge/init")
    public Map<String, Object> initChallenge() {
        return gydevGuardService.initChallenge();
    }

    @GetMapping("/submit-get")
    public Map<String, Object> submitGet(
            @RequestParam("content") String content,
            @RequestParam("gydev_token") String gydevToken,
            @RequestParam("Gydev-Sentinel-Proof-Token") String sentinelProofToken,
            HttpServletRequest request) {
        GydevEvaluationPayload payload = new GydevEvaluationPayload();
        payload.setContent(content);
        payload.setGydevToken(gydevToken);
        payload.setGydevSentinelProofToken(sentinelProofToken);
        GydevEvaluationResult result = gydevGuardService.evaluate(request, payload);
        return result.toMap();
    }

    @PostMapping("/submit-post")
    public Map<String, Object> submitPost(
            @RequestBody Map<String, Object> body,
            @RequestHeader(value = "Gydev-Sentinel-Proof-Token", required = false) String sentinelProofHeader,
            HttpServletRequest request) {
        GydevEvaluationPayload payload = new GydevEvaluationPayload();
        payload.setContent(String.valueOf(body.getOrDefault("content", "")));
        payload.setGydevToken(String.valueOf(body.getOrDefault("gydev_token", "")));

        String sentinelProofBody = String.valueOf(body.getOrDefault("Gydev-Sentinel-Proof-Token", ""));
        payload.setGydevSentinelProofToken(sentinelProofHeader != null && !sentinelProofHeader.isBlank()
                ? sentinelProofHeader : sentinelProofBody);
        GydevEvaluationResult result = gydevGuardService.evaluate(request, payload);

        Map<String, Object> out = new LinkedHashMap<>(result.toMap());
        out.put("transport", "post");
        return out;
    }
}

