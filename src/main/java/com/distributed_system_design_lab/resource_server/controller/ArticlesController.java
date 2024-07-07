package com.distributed_system_design_lab.resource_server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 控制器類，用於處理 /articles 請求並返回文章數據。
 * 
 * @author vinskao
 * @version 0.1
 */
@RestController
public class ArticlesController {
    /**
     * 處理 GET /articles 請求，返回文章列表。
     *
     * @return 文章標題的字符串數組
     */
    @GetMapping("/articles")
    public String[] getArticles() {
        return new String[] { "Article 1", "Article 2", "Article 3" };
    }
}
