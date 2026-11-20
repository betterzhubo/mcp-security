/*
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

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class McpServerConfigurationTests {

	@Test
	void corsConfigurationUsesExplicitOriginsAndMcpHeaders() {
		CorsConfigurationSource source = new McpServerConfiguration()
			.corsConfigurationSource(List.of("http://localhost:6274", "https://console.example.com"));

		CorsConfiguration configuration = source.getCorsConfiguration(new MockHttpServletRequest("OPTIONS", "/mcp"));

		assertThat(configuration).isNotNull();
		assertThat(configuration.getAllowedOriginPatterns())
			.containsExactly("http://localhost:6274", "https://console.example.com");
		assertThat(configuration.getAllowedMethods()).containsExactly("GET", "POST", "DELETE", "OPTIONS");
		assertThat(configuration.getAllowedHeaders()).contains("Authorization", "Content-Type", "Mcp-Session-Id",
				"Mcp-Protocol-Version", "Last-Event-ID");
		assertThat(configuration.getExposedHeaders()).contains("Mcp-Session-Id", "WWW-Authenticate",
				"Mcp-Protocol-Version");
		assertThat(configuration.getAllowCredentials()).isTrue();
	}

	@Test
	void corsConfigurationRejectsGlobalWildcardWithCredentials() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new McpServerConfiguration().corsConfigurationSource(List.of("*")));
	}

}
