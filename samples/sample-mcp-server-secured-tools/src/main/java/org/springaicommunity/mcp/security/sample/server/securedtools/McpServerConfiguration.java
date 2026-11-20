/*
 * Copyright 2025-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springaicommunity.mcp.security.sample.server.securedtools;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.Assert;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import static org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer.mcpServerOAuth2;

/**
 * @author Daniel Garnier-Moiroux
 */
@Configuration
@EnableMethodSecurity
class McpServerConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http,
			@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUrl,
			CorsConfigurationSource corsConfigurationSource) throws Exception {
		return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
			.with(mcpServerOAuth2(), (mcpAuthorization) -> {
				mcpAuthorization.authorizationServer(issuerUrl).resourcePath("/mcp");
			})
			.cors(cors -> cors.configurationSource(corsConfigurationSource))
			.csrf(CsrfConfigurer::disable)
			.build();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource(
			@Value("${mcp.security.cors.allowed-origin-patterns:http://localhost:6274}") List<String> allowedOriginPatterns) {
		Assert.notEmpty(allowedOriginPatterns, "At least one allowed CORS origin must be configured");
		Assert.noNullElements(allowedOriginPatterns, "Allowed CORS origins must not contain null values");
		Assert.isTrue(allowedOriginPatterns.stream().noneMatch(origin -> "*".equals(origin.trim())),
				"Wildcard CORS origins are not allowed when credentials are enabled");
		Assert.isTrue(allowedOriginPatterns.stream().allMatch(origin -> !origin.isBlank()),
				"Allowed CORS origins must not be blank");

		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOriginPatterns(allowedOriginPatterns.stream().map(String::trim).toList());
		configuration.setAllowedMethods(List.of("GET", "POST", "DELETE", "OPTIONS"));
		configuration.setAllowedHeaders(List.of("Accept", "Authorization", "Content-Type", "Origin",
				"Mcp-Session-Id", "Mcp-Protocol-Version", "Last-Event-ID"));
		configuration.setExposedHeaders(List.of("Mcp-Session-Id", "Mcp-Protocol-Version", "WWW-Authenticate"));
		configuration.setAllowCredentials(true);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
