/*
 * Copyright 2026-2026 the original author or authors.
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

package org.springaicommunity.mcp.security.server.apikey.authentication;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyImpl;
import org.springaicommunity.mcp.security.server.apikey.memory.ApiKeyEntityImpl;
import org.springaicommunity.mcp.security.server.apikey.memory.InMemoryApiKeyEntityRepository;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ApiKeyAuthenticationProvider}.
 */
class ApiKeyAuthenticationProviderTests {

	@Test
	void authenticatedApiKeyCarriesConfiguredAuthorities() {
		var readAuthority = new SimpleGrantedAuthority("SCOPE_weather.read");
		var apiKeyEntity = ApiKeyEntityImpl.builder()
			.id("api01")
			.secret("test-secret")
			.name("weather read key")
			.authorities(List.of(readAuthority))
			.build();
		var repository = new InMemoryApiKeyEntityRepository<>(List.of(apiKeyEntity));
		var provider = new ApiKeyAuthenticationProvider<>(repository);

		var authentication = provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("api01.test-secret")));

		assertThat(authentication).isNotNull();
		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getAuthorities()).containsExactlyElementsOf(List.of(readAuthority));
	}

}
