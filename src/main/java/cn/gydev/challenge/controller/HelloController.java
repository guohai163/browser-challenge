package cn.gydev.challenge.controller;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 用于验证应用是否正常启动的最小示例接口。
 */
@RestController
public class HelloController {

    /**
     * 返回简单的健康检查风格响应。
     *
     * @return 简单 JSON 结果
     */
    @GetMapping("/hello")
    public Map<String, String> hello() {
        return Map.of("message", "Hello, Spring Boot 4 + JDK 21");
    }
}
