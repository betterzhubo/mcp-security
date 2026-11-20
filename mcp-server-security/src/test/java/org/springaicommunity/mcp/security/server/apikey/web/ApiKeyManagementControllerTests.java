package org.springaicommunity.mcp.security.server.apikey.web;

import java.util.List;
import java.util.Objects;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;
import org.springaicommunity.mcp.security.server.apikey.memory.InMemoryApiKeyEntityRepository;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ApiKeyManagementControllerTests {

	private static final TestingAuthenticationToken ADMIN = new TestingAuthenticationToken("admin", "password",
			ApiKeyManagementController.MANAGEMENT_AUTHORITY);

	private static final TestingAuthenticationToken USER = new TestingAuthenticationToken("user", "password",
			"SCOPE_weather.read");

	private InMemoryApiKeyEntityRepository<ApiKeyEntity> repository;

	private ApiKeyManagementController controller;

	@BeforeEach
	void setUp() {
		this.repository = new InMemoryApiKeyEntityRepository<>();
		this.controller = new ApiKeyManagementController(this.repository);
	}

	@Test
	void createsApiKeyAndReturnsPlaintextSecretOnlyAtCreation() {
		var response = this.controller
			.create(new ApiKeyManagementController.CreateApiKeyRequest(List.of("SCOPE_weather.read"), null), ADMIN);
		var body = Objects.requireNonNull(response.getBody());
		ApiKeyEntity stored = Objects.requireNonNull(this.repository.findByKeyId(body.keyId()));

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
		assertThat(body.keyId()).startsWith("mcp_");
		assertThat(body.secret()).isNotBlank();
		assertThat(stored.getSecret()).isNotEqualTo(body.secret());
		assertThat(
				PasswordEncoderFactories.createDelegatingPasswordEncoder().matches(body.secret(), stored.getSecret()))
			.isTrue();
		assertThat(body.authorities()).containsExactly("SCOPE_weather.read");

		var metadata = this.controller.get(body.keyId(), ADMIN);
		assertThat(metadata.keyId()).isEqualTo(body.keyId());
		assertThat(metadata.enabled()).isTrue();
		assertThat(metadata.authorities()).containsExactly("SCOPE_weather.read");
	}

	@Test
	void rejectsMissingManagementAuthority() {
		assertThatThrownBy(() -> this.controller
			.create(new ApiKeyManagementController.CreateApiKeyRequest(List.of("SCOPE_weather.read"), null), USER))
			.isInstanceOf(AccessDeniedException.class);
		assertThat(this.repository.findByKeyId("any-key")).isNull();
	}

	@Test
	void rejectsDelegatingManagementAuthority() {
		assertThatThrownBy(() -> this.controller.create(new ApiKeyManagementController.CreateApiKeyRequest(
				List.of(ApiKeyManagementController.MANAGEMENT_AUTHORITY), null), ADMIN))
			.isInstanceOf(ResponseStatusException.class)
			.satisfies(exception -> assertThat(((ResponseStatusException) exception).getStatusCode())
				.isEqualTo(HttpStatus.BAD_REQUEST));
	}

	@Test
	void rejectsDuplicateAuthorities() {
		assertThatThrownBy(() -> this.controller.create(new ApiKeyManagementController.CreateApiKeyRequest(
				List.of("SCOPE_weather.read", "SCOPE_weather.read"), null), ADMIN))
			.isInstanceOf(ResponseStatusException.class)
			.satisfies(exception -> assertThat(((ResponseStatusException) exception).getStatusCode())
				.isEqualTo(HttpStatus.BAD_REQUEST));
	}

	@Test
	void rejectsExpiredAtCreation() {
		assertThatThrownBy(() -> this.controller.create(new ApiKeyManagementController.CreateApiKeyRequest(
				List.of("SCOPE_weather.read"), java.time.Instant.parse("2000-01-01T00:00:00Z")), ADMIN))
			.isInstanceOf(ResponseStatusException.class)
			.satisfies(exception -> assertThat(((ResponseStatusException) exception).getStatusCode())
				.isEqualTo(HttpStatus.BAD_REQUEST));
	}

	@Test
	void enablesDisablesAndRevokesApiKey() {
		var created = Objects.requireNonNull(this.controller
			.create(new ApiKeyManagementController.CreateApiKeyRequest(List.of("SCOPE_weather.read"), null), ADMIN)
			.getBody());

		var disabled = this.controller.disable(created.keyId(), ADMIN);
		assertThat(disabled.enabled()).isFalse();
		assertThat(this.repository.findByKeyId(created.keyId())).isNotNull();

		var enabled = this.controller.enable(created.keyId(), ADMIN);
		assertThat(enabled.enabled()).isTrue();

		assertThat(this.controller.revoke(created.keyId(), ADMIN).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
		assertThat(this.repository.findByKeyId(created.keyId())).isNull();
	}

	@Test
	void rotatesKeyWithoutInvalidatingTheCurrentKey() {
		var original = Objects.requireNonNull(this.controller
			.create(new ApiKeyManagementController.CreateApiKeyRequest(List.of("SCOPE_weather.read"), null), ADMIN)
			.getBody());

		var replacementResponse = this.controller.rotate(original.keyId(), null, ADMIN);
		var replacement = Objects.requireNonNull(replacementResponse.getBody());

		assertThat(replacementResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
		assertThat(replacement.keyId()).isNotEqualTo(original.keyId());
		assertThat(replacement.secret()).isNotEqualTo(original.secret());
		assertThat(this.repository.isEnabled(original.keyId())).isTrue();
		assertThat(this.repository.isEnabled(replacement.keyId())).isTrue();
		assertThat(replacement.authorities()).containsExactly("SCOPE_weather.read");

		this.controller.revoke(original.keyId(), ADMIN);
		assertThat(this.repository.isEnabled(original.keyId())).isFalse();
		assertThat(this.repository.isEnabled(replacement.keyId())).isTrue();
	}

	@Test
	void doesNotAllowRotatingDisabledOrMissingKeys() {
		assertThatThrownBy(() -> this.controller.rotate("missing", null, ADMIN))
			.isInstanceOf(ResponseStatusException.class)
			.satisfies(exception -> assertThat(((ResponseStatusException) exception).getStatusCode())
				.isEqualTo(HttpStatus.NOT_FOUND));

		var created = Objects.requireNonNull(this.controller
			.create(new ApiKeyManagementController.CreateApiKeyRequest(List.of("SCOPE_weather.read"), null), ADMIN)
			.getBody());
		this.repository.disableApiKey(created.keyId());

		assertThatThrownBy(() -> this.controller.rotate(created.keyId(), null, ADMIN))
			.isInstanceOf(ResponseStatusException.class)
			.satisfies(exception -> assertThat(((ResponseStatusException) exception).getStatusCode())
				.isEqualTo(HttpStatus.CONFLICT));
	}

}
