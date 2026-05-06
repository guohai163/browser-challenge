package cn.gydev.challenge.controller;

import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 提供演示页面所需的应用元信息接口。
 */
@RestController
public class AppMetaController {

    @Value("${app.version:unknown}")
    private String version;

    @Value("${app.published-at:unknown}")
    private String publishedAt;

    /**
     * 返回当前应用版本与发布时间信息。
     *
     * @return 元信息结果
     */
    @GetMapping("/api/meta")
    public Map<String, String> meta() {
        return Map.of(
                "version", version,
                "publishedAt", publishedAt);
    }
}
