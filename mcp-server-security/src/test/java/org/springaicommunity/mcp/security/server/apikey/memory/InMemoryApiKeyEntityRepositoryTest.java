package org.springaicommunity.mcp.security.server.apikey.memory;

import java.util.ArrayList;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InMemoryApiKeyEntityRepositoryTest {

	private final ApiKeyEntityImpl apiKeyEntity = ApiKeyEntityImpl.builder()
		.id("api01")
		.secret("test-secret")
		.name("test key")
		.authorities(List.of(new SimpleGrantedAuthority("SCOPE_weather.read")))
		.build();

	private final InMemoryApiKeyEntityRepository<@NonNull ApiKeyEntityImpl> repository = new InMemoryApiKeyEntityRepository<>(
			List.of(this.apiKeyEntity));

	@Test
	void loadsKey() {
		var key = this.repository.findByKeyId("api01");

		assertThat(key).isNotNull();
		assertThat(key).isNotSameAs(this.apiKeyEntity);
		assertThat(key.getId()).isEqualTo(this.apiKeyEntity.getId());
		assertThat(key.getSecret()).isEqualTo(this.apiKeyEntity.getSecret());
		assertThat(key.getName()).isEqualTo(this.apiKeyEntity.getName());
		assertThat(key.getAuthorities()).containsExactlyElementsOf(this.apiKeyEntity.getAuthorities());
		assertThatThrownBy(() -> key.getAuthorities().add(new SimpleGrantedAuthority("SCOPE_weather.write")))
			.isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	void missingKey() {
		var key = this.repository.findByKeyId("does-not-exist");
		assertThat(key).isNull();
	}

	@Test
	void containsKey() {
		assertThat(this.repository.containsApiKey("api01")).isTrue();
		assertThat(this.repository.containsApiKey("does-not-exist")).isFalse();
	}

	@Test
	void addApiKey() {
		var addedKey = ApiKeyEntityImpl.builder()
			.id("api02")
			.secret("custom-secret")
			.name("added key")
			.authorities(List.of(new SimpleGrantedAuthority("SCOPE_weather.write")))
			.build();

		this.repository.addApiKey(addedKey);
		var key = this.repository.findByKeyId("api02");

		assertThat(key).isNotNull();
		assertThat(key).isNotSameAs(addedKey);
		assertThat(key.getId()).isEqualTo(addedKey.getId());
		assertThat(key.getSecret()).isEqualTo(addedKey.getSecret());
		assertThat(key.getName()).isEqualTo(addedKey.getName());
		assertThat(key.getAuthorities()).containsExactlyElementsOf(addedKey.getAuthorities());
	}

	@Test
	void builderCopiesAuthorities() {
		var authorities = new ArrayList<>(List.of(new SimpleGrantedAuthority("SCOPE_weather.read")));
		var apiKey = ApiKeyEntityImpl.builder()
			.id("api03")
			.secret("test-secret")
			.name("copied authorities")
			.authorities(authorities)
			.build();

		authorities.add(new SimpleGrantedAuthority("SCOPE_weather.write"));

		assertThat(apiKey.getAuthorities()).containsExactly(new SimpleGrantedAuthority("SCOPE_weather.read"));
	}

	@Test
	void addApiKeyOverrides() {
		var addedKey = ApiKeyEntityImpl.builder().id("api02").secret("custom-secret").name("added key").build();
		var addedKeyOverride = ApiKeyEntityImpl.builder()
			.id("api02")
			.secret("custom-secret")
			.name("added key")
			.authorities(List.of(new SimpleGrantedAuthority("SCOPE_weather.write")))
			.build();

		this.repository.addApiKey(addedKey);
		this.repository.addApiKey(addedKeyOverride);
		var key = this.repository.findByKeyId("api02");

		assertThat(key).isNotNull();
		assertThat(key).isNotSameAs(addedKeyOverride);
		assertThat(key.getId()).isEqualTo(addedKeyOverride.getId());
		assertThat(key.getSecret()).isEqualTo(addedKeyOverride.getSecret());
		assertThat(key.getName()).isEqualTo(addedKeyOverride.getName());
		assertThat(key.getAuthorities()).containsExactlyElementsOf(addedKeyOverride.getAuthorities());
	}

	@Test
	void removeApiKey() {
		this.repository.removeApiKey("api01");
		this.repository.removeApiKey("does-not-exist");

		assertThat(this.repository.containsApiKey("api01")).isFalse();
	}

}
