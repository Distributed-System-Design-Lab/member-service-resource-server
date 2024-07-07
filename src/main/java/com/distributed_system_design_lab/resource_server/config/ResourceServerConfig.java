package com.distributed_system_design_lab.resource_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.Customizer;

/**
 * 配置資源服務器的安全設置。
 * 
 * @author vinskao
 * @version 0.1
 */
@Configuration
@EnableWebSecurity
public class ResourceServerConfig {

  /**
   * 配置安全過濾鏈 bean。
   *
   * @param http HttpSecurity 配置對象
   * @return 配置好的 SecurityFilterChain 實例
   * @throws Exception 配置過程中可能拋出的異常
   */
  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    // 配置 HttpSecurity 以確保 /articles/** 路徑下的請求需要特定的授權範圍
    http.securityMatcher("/articles/**") // 設置匹配的 URL 模式
        .authorizeHttpRequests(authorize -> authorize.anyRequest() // 授權請求
            .hasAuthority("SCOPE_articles.read")) // 要求請求具有 "SCOPE_articles.read" 的授權範圍
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())); // 配置 OAuth2 資源服務器以使用 JWT
    return http.build(); // 構建 SecurityFilterChain 實例
  }
}
