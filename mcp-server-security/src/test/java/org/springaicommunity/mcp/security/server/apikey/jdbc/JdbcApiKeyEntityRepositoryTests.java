/*
 * Copyright 2025-2026 the original author or authors.
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

package org.springaicommunity.mcp.security.server.apikey.jdbc;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyImpl;
import org.springaicommunity.mcp.security.server.apikey.authentication.ApiKeyAuthenticationProvider;
import org.springaicommunity.mcp.security.server.apikey.authentication.ApiKeyAuthenticationToken;
import org.springaicommunity.mcp.security.server.apikey.memory.ApiKeyEntityImpl;

import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JdbcApiKeyEntityRepositoryTests {

	private DriverManagerDataSource dataSource;

	private JdbcTemplate jdbcTemplate;

	private JdbcApiKeyEntityRepository repository;

	@BeforeEach
	void setUp() {
		this.dataSource = new DriverManagerDataSource();
		this.dataSource.setDriverClassName("org.h2.Driver");
		this.dataSource.setUrl("jdbc:h2:mem:api-keys-" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1");
		this.dataSource.setUsername("sa");
		this.dataSource.setPassword("");
		new ResourceDatabasePopulator(new ClassPathResource(
				"org/springaicommunity/mcp/security/server/apikey/jdbc/schema.sql")).execute(this.dataSource);
		this.jdbcTemplate = new JdbcTemplate(this.dataSource);
		this.repository = new JdbcApiKeyEntityRepository(this.jdbcTemplate,
				new DataSourceTransactionManager(this.dataSource));
	}

	@AfterEach
	void tearDown() {
		this.jdbcTemplate.execute("DROP ALL OBJECTS");
	}

	@Test
	void persistsEncodedSecretAuthoritiesAndExpiration() {
		var expiration = Instant.parse("2030-01-01T00:00:00Z");
		var entity = ApiKeyEntityImpl.builder()
			.id("api01")
			.secret("test-secret")
			.name("weather reader")
			.authorities(List.of(new SimpleGrantedAuthority("SCOPE_weather.read")))
			.expiresAt(expiration)
			.build();

		this.repository.addApiKey(entity);
		var stored = this.repository.findByKeyId("api01");

		assertThat(stored).isNotNull();
		assertThat(stored.getId()).isEqualTo("api01");
		assertThat(stored.getSecret()).isEqualTo(entity.getSecret());
		assertThat(stored.getSecret()).isNotEqualTo("test-secret");
		assertThat(stored.getExpiresAt()).isEqualTo(expiration);
		assertThat(stored.getAuthorities()).containsExactly(new SimpleGrantedAuthority("SCOPE_weather.read"));
		assertThat(this.repository.isEnabled("api01")).isTrue();
	}

	@Test
	void authenticatesAgainstPersistedKey() {
		var entity = ApiKeyEntityImpl.builder()
			.id("api01")
			.secret("test-secret")
			.name("weather reader")
			.authorities(List.of(new SimpleGrantedAuthority("SCOPE_weather.read")))
			.build();
		this.repository.addApiKey(entity);
		var provider = new ApiKeyAuthenticationProvider<>(this.repository);

		var authentication = provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("api01.test-secret")));

		assertThat(authentication).isNotNull();
		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getAuthorities())
			.containsExactly(new SimpleGrantedAuthority("SCOPE_weather.read"));
	}

	@Test
	void enablesDisablesAndRevokesPersistedKeys() {
		this.repository.addApiKey(key("api01", "test-secret"));

		assertThat(this.repository.disableApiKey("api01")).isTrue();
		assertThat(this.repository.isEnabled("api01")).isFalse();
		assertThat(this.repository.findByKeyId("api01")).isNotNull();

		assertThat(this.repository.enableApiKey("api01")).isTrue();
		assertThat(this.repository.isEnabled("api01")).isTrue();

		assertThat(this.repository.revokeApiKey("api01")).isTrue();
		assertThat(this.repository.findByKeyId("api01")).isNull();
		assertThat(this.repository.isEnabled("api01")).isFalse();
	}

	@Test
	void rotatesKeysWithoutInvalidatingCurrentKey() {
		this.repository.addApiKey(key("old-key", "old-secret"));
		var replacement = key("new-key", "new-secret");

		assertThat(this.repository.rotateApiKey("old-key", replacement)).isTrue();
		assertThat(this.repository.isEnabled("old-key")).isTrue();
		assertThat(this.repository.isEnabled("new-key")).isTrue();
		assertThat(this.repository.findByKeyId("old-key")).isNotNull();
		assertThat(this.repository.findByKeyId("new-key")).isNotNull();

		assertThat(this.repository.revokeApiKey("old-key")).isTrue();
		assertThat(this.repository.findByKeyId("old-key")).isNull();
		assertThat(this.repository.findByKeyId("new-key")).isNotNull();
	}

	@Test
	void rejectsRotationForMissingDisabledOrDuplicateKeys() {
		this.repository.addApiKey(key("old-key", "old-secret"));
		this.repository.addApiKey(key("taken-key", "taken-secret"));

		assertThat(this.repository.rotateApiKey("missing", key("new-key", "new-secret"))).isFalse();
		assertThat(this.repository.rotateApiKey("old-key", key("taken-key", "other-secret"))).isFalse();
		assertThat(this.repository.disableApiKey("old-key")).isTrue();
		assertThat(this.repository.rotateApiKey("old-key", key("new-key", "new-secret"))).isFalse();
		assertThat(this.repository.findByKeyId("new-key")).isNull();
	}

	@Test
	void rollsBackReplacementWhenAuthorityInsertFails() {
		this.repository.addApiKey(key("old-key", "old-secret"));
		var replacement = ApiKeyEntityImpl.builder()
			.id("new-key")
			.secret("new-secret")
			.name("new key")
			.authorities(List.of(new SimpleGrantedAuthority("SCOPE_read"),
					new SimpleGrantedAuthority("SCOPE_read")))
			.build();

		assertThat(this.repository.rotateApiKey("old-key", replacement)).isFalse();
		assertThat(this.repository.findByKeyId("new-key")).isNull();
		assertThat(this.repository.isEnabled("old-key")).isTrue();
	}

	@Test
	void rejectsAuthenticationAfterPersistedKeyIsDisabledOrRevoked() {
		this.repository.addApiKey(key("api01", "test-secret"));
		var provider = new ApiKeyAuthenticationProvider<>(this.repository);
		this.repository.disableApiKey("api01");

		assertThatThrownBy(() -> provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("api01.test-secret"))))
			.isInstanceOf(BadCredentialsException.class)
			.hasMessage("Invalid API key");

		this.repository.enableApiKey("api01");
		this.repository.revokeApiKey("api01");
		assertThatThrownBy(() -> provider
			.authenticate(ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from("api01.test-secret"))))
			.isInstanceOf(BadCredentialsException.class)
			.hasMessage("Invalid API key");
	}

	private ApiKeyEntityImpl key(String id, String secret) {
		return ApiKeyEntityImpl.builder().id(id).secret(secret).name(id).build();
	}

}
