package com.example.customerprofile.config;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
public class ResourceServerConfig {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    // @formatter:off
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorizeRequests -> {
                    authorizeRequests.requestMatchers(HttpMethod.GET, "/api/customer-profiles/**").hasAuthority("SCOPE_message.read");
                    authorizeRequests.requestMatchers(HttpMethod.POST, "/api/customer-profiles/**").hasAuthority("SCOPE_message.write");
                })
                .cors()
                .configurationSource(new PermissiveCorsConfigurationSource())
                .and()
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .build();
    }
    // @formatter:on

    @EventListener
    public void handleContextRefresh(ContextRefreshedEvent event) {
        logger.info("Authorization server issuer URI: " + issuerUri);
    }

    private static class PermissiveCorsConfigurationSource implements CorsConfigurationSource {
        /**
         * Return a {@link CorsConfiguration} based on the incoming request.
         *
         * @param request
         * @return the associated {@link CorsConfiguration}, or {@code null} if none
         */
        @Override
        public CorsConfiguration getCorsConfiguration(final HttpServletRequest request) {
            final CorsConfiguration configuration = new CorsConfiguration();
            configuration.setAllowCredentials(false);
            configuration.setAllowedOriginPatterns(Collections.singletonList("*"));
            configuration.setAllowedHeaders(Collections.singletonList("*"));
            configuration.setExposedHeaders(Collections.singletonList("*"));
            configuration.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
            return configuration;
        }
    }
}
