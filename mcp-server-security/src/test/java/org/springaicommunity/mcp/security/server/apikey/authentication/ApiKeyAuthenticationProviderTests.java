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

import java.time.Clock;
import java.util.ArrayList;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyImpl;
import org.springaicommunity.mcp.security.server.apikey.audit.ApiKeyAuditEvent;
import org.springaicommunity.mcp.security.server.apikey.memory.ApiKeyEntityImpl;
import org.springaicommunity.mcp.security.server.apikey.memory.InMemoryApiKeyEntityRepository;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link ApiKeyAuthenticationProvider}.
 */
class ApiKeyAuthenticationProviderTests {

	private static final Instant NOW = Instant.parse("2026-11-20T08:00:00Z");

	@Test
	void auditsSuccessfulAndFailedAuthenticationWithoutCredentialMaterial() {
		var entity = ApiKeyEntityImpl.builder().id("audited").secret("test-secret").name("audited key").build();
		var repository = new InMemoryApiKeyEntityRepository<>(List.of(entity));
		var events = new ArrayList<ApiKeyAuditEvent>();
		var provider = new ApiKeyAuthenticationProvider<>(repository, Clock.fixed(NOW, ZoneOffset.UTC), events::add);

		provider.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("audited.test-secret")));

		assertThatThrownBy(() -> provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("audited.wrong-secret"))))
			.isInstanceOf(BadCredentialsException.class);

		assertThat(events).hasSize(2);
		assertThat(events).extracting(ApiKeyAuditEvent::action).containsOnly(ApiKeyAuditEvent.Action.AUTHENTICATE);
		assertThat(events).extracting(ApiKeyAuditEvent::outcome)
			.containsExactly(ApiKeyAuditEvent.Outcome.SUCCESS, ApiKeyAuditEvent.Outcome.FAILURE);
		assertThat(events).extracting(ApiKeyAuditEvent::reason)
			.containsExactly(ApiKeyAuditEvent.Reason.NONE, ApiKeyAuditEvent.Reason.SECRET_MISMATCH);
		assertThat(events).allSatisfy(event -> {
			assertThat(event.keyId()).isEqualTo("audited");
			assertThat(event.authorities()).isEmpty();
			assertThat(event.toString()).doesNotContain("test-secret", "wrong-secret");
		});
	}

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
		var provider = new ApiKeyAuthenticationProvider<>(repository, Clock.fixed(NOW, ZoneOffset.UTC));

		var authentication = provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("api01.test-secret")));

		assertThat(authentication).isNotNull();
		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities().iterator().next().getAuthority()).isEqualTo("SCOPE_weather.read");
	}

	@Test
	void rejectsExpiredApiKey() {
		var expiredKey = ApiKeyEntityImpl.builder()
			.id("expired")
			.secret("test-secret")
			.name("expired key")
			.expiresAt(NOW.minusSeconds(1))
			.build();
		var repository = new InMemoryApiKeyEntityRepository<>(List.of(expiredKey));
		var provider = new ApiKeyAuthenticationProvider<>(repository, Clock.fixed(NOW, ZoneOffset.UTC));

		assertThatThrownBy(() -> provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("expired.test-secret"))))
			.isInstanceOf(BadCredentialsException.class)
			.hasMessage("API key has expired");
	}

	@Test
	void rejectsApiKeyAtExactExpirationInstant() {
		var expiringKey = ApiKeyEntityImpl.builder()
			.id("expiring")
			.secret("test-secret")
			.name("expiring key")
			.expiresAt(NOW)
			.build();
		var repository = new InMemoryApiKeyEntityRepository<>(List.of(expiringKey));
		var provider = new ApiKeyAuthenticationProvider<>(repository, Clock.fixed(NOW, ZoneOffset.UTC));

		assertThatThrownBy(() -> provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("expiring.test-secret"))))
			.isInstanceOf(BadCredentialsException.class)
			.hasMessage("API key has expired");
	}

	@Test
	void rejectsDisabledApiKey() {
		var apiKeyEntity = ApiKeyEntityImpl.builder().id("disabled").secret("test-secret").name("disabled key").build();
		var repository = new InMemoryApiKeyEntityRepository<>(List.of(apiKeyEntity));
		repository.disableApiKey("disabled");
		var provider = new ApiKeyAuthenticationProvider<>(repository, Clock.fixed(NOW, ZoneOffset.UTC));

		assertThatThrownBy(() -> provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("disabled.test-secret"))))
			.isInstanceOf(BadCredentialsException.class)
			.hasMessage("Invalid API key");
	}

	@Test
	void rejectsRevokedApiKey() {
		var apiKeyEntity = ApiKeyEntityImpl.builder().id("revoked").secret("test-secret").name("revoked key").build();
		var repository = new InMemoryApiKeyEntityRepository<>(List.of(apiKeyEntity));
		repository.revokeApiKey("revoked");
		var provider = new ApiKeyAuthenticationProvider<>(repository, Clock.fixed(NOW, ZoneOffset.UTC));

		assertThatThrownBy(() -> provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("revoked.test-secret"))))
			.isInstanceOf(BadCredentialsException.class)
			.hasMessage("Invalid API key");
	}

	@Test
	void supportsAuthenticationDuringRotationAndAfterOldKeyRevocation() {
		var currentKey = ApiKeyEntityImpl.builder().id("current").secret("current-secret").name("current key").build();
		var replacementKey = ApiKeyEntityImpl.builder()
			.id("replacement")
			.secret("replacement-secret")
			.name("replacement key")
			.build();
		var repository = new InMemoryApiKeyEntityRepository<>(List.of(currentKey));
		var provider = new ApiKeyAuthenticationProvider<>(repository, Clock.fixed(NOW, ZoneOffset.UTC));

		assertThat(repository.rotateApiKey("current", replacementKey)).isTrue();

		var currentAuthentication = provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("current.current-secret")));
		var replacementAuthentication = provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("replacement.replacement-secret")));

		assertThat(currentAuthentication).isNotNull();
		assertThat(currentAuthentication.isAuthenticated()).isTrue();
		assertThat(replacementAuthentication).isNotNull();
		assertThat(replacementAuthentication.isAuthenticated()).isTrue();

		assertThat(repository.revokeApiKey("current")).isTrue();
		assertThatThrownBy(() -> provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("current.current-secret"))))
			.isInstanceOf(BadCredentialsException.class)
			.hasMessage("Invalid API key");

		var authenticationAfterRevocation = provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("replacement.replacement-secret")));
		assertThat(authenticationAfterRevocation).isNotNull();
		assertThat(authenticationAfterRevocation.isAuthenticated()).isTrue();
	}

	@Test
	void acceptsApiKeyBeforeExpirationInstant() {
		var validKey = ApiKeyEntityImpl.builder()
			.id("valid")
			.secret("test-secret")
			.name("valid key")
			.expiresAt(NOW.plusSeconds(1))
			.build();
		var repository = new InMemoryApiKeyEntityRepository<>(List.of(validKey));
		var provider = new ApiKeyAuthenticationProvider<>(repository, Clock.fixed(NOW, ZoneOffset.UTC));

		var authentication = provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("valid.test-secret")));

		assertThat(authentication).isNotNull();
		assertThat(authentication.isAuthenticated()).isTrue();
	}

}
