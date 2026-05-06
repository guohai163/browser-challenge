package cn.gydev.challenge.controller;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Minimal HTTP endpoint used to verify the application boots correctly.
 */
@RestController
public class HelloController {

    /**
     * Returns a simple health-style response.
     *
     * @return a small JSON payload
     */
    @GetMapping("/hello")
    public Map<String, String> hello() {
        return Map.of("message", "Hello, Spring Boot 4 + JDK 21");
    }
}
