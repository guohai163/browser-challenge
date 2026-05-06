package cn.gydev.challenge.controller;

import cn.gydev.challenge.service.TlsClassifierService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 基于 TLS 相关信号与请求头特征对调用方类型进行判别的接口。
 */
@RestController
@RequestMapping("/api")
public class TlsController {

    private final TlsClassifierService tlsClassifierService;

    public TlsController(TlsClassifierService tlsClassifierService) {
        this.tlsClassifierService = tlsClassifierService;
    }

    /**
     * 将请求分类为 browser / program / unknown。
     *
     * @param request 当前请求
     * @return 分类结果
     */
    @GetMapping("/tls")
    public Map<String, Object> tls(HttpServletRequest request) {
        return tlsClassifierService.classify(request);
    }
}
