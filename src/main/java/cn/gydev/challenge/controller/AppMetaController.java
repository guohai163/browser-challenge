package cn.gydev.challenge.controller;

import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes simple app metadata for demo page rendering.
 */
@RestController
public class AppMetaController {

    @Value("${app.version:unknown}")
    private String version;

    @Value("${app.published-at:unknown}")
    private String publishedAt;

    /**
     * Returns current app version metadata.
     *
     * @return metadata map
     */
    @GetMapping("/api/meta")
    public Map<String, String> meta() {
        return Map.of(
                "version", version,
                "publishedAt", publishedAt);
    }
}
