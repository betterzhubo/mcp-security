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

package org.springaicommunity.mcp.security.server.apikey.web;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityManagementRepository;
import org.springaicommunity.mcp.security.server.apikey.memory.ApiKeyEntityImpl;

import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Opt-in REST API for managing MCP API keys.
 *
 * <p>
 * Enable this controller with the {@code mcp-api-key-management} Spring profile and
 * provide an {@link ApiKeyEntityManagementRepository} bean. Every operation checks the
 * {@code SCOPE_mcp.apikeys.manage} authority directly, independently of method-security
 * configuration.
 * </p>
 *
 * <p>
 * A newly generated secret is returned only by the create and rotate operations. The
 * repository receives an encoded secret, never the plaintext value.
 * </p>
 */
@RestController
@Profile("mcp-api-key-management")
@RequestMapping("/api/keys")
public class ApiKeyManagementController {

	public static final String MANAGEMENT_AUTHORITY = "SCOPE_mcp.apikeys.manage";

	private static final int SECRET_BYTES = 32;

	private final ApiKeyEntityManagementRepository<ApiKeyEntity> repository;

	private final Clock clock;

	private final SecureRandom secureRandom;

	public ApiKeyManagementController(ApiKeyEntityManagementRepository<ApiKeyEntity> repository) {
		this(repository, Clock.systemUTC(), new SecureRandom());
	}

	ApiKeyManagementController(ApiKeyEntityManagementRepository<ApiKeyEntity> repository, Clock clock,
			SecureRandom secureRandom) {
		Assert.notNull(repository, "repository must not be null");
		Assert.notNull(clock, "clock must not be null");
		Assert.notNull(secureRandom, "secureRandom must not be null");
		this.repository = repository;
		this.clock = clock;
		this.secureRandom = secureRandom;
	}

	@PostMapping
	public ResponseEntity<ApiKeyCreatedResponse> create(@RequestBody CreateApiKeyRequest request,
			@Nullable Authentication authentication) {
		requireManagementAuthority(authentication);
		List<GrantedAuthority> authorities = validateAuthorities(request.authorities());
		@Nullable Instant expiresAt = validateExpiration(request.expiresAt());
		GeneratedKey generatedKey = generateKey(authorities, expiresAt);
		this.repository.addApiKey(generatedKey.entity());
		return ResponseEntity.status(HttpStatus.CREATED).body(generatedKey.response());
	}

	@GetMapping("/{keyId}")
	public ApiKeyMetadataResponse get(@PathVariable String keyId, @Nullable Authentication authentication) {
		requireManagementAuthority(authentication);
		@Nullable ApiKeyEntity entity = this.repository.findByKeyId(keyId);
		if (entity == null) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "API key not found");
		}
		return metadata(entity);
	}

	@PostMapping("/{keyId}/enable")
	public ApiKeyMetadataResponse enable(@PathVariable String keyId,
			@Nullable Authentication authentication) {
		requireManagementAuthority(authentication);
		if (!this.repository.enableApiKey(keyId)) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "API key not found");
		}
		return getMetadataAfterLifecycleChange(keyId);
	}

	@PostMapping("/{keyId}/disable")
	public ApiKeyMetadataResponse disable(@PathVariable String keyId,
			@Nullable Authentication authentication) {
		requireManagementAuthority(authentication);
		if (!this.repository.disableApiKey(keyId)) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "API key not found");
		}
		return getMetadataAfterLifecycleChange(keyId);
	}

	@DeleteMapping("/{keyId}")
	public ResponseEntity<Void> revoke(@PathVariable String keyId,
			@Nullable Authentication authentication) {
		requireManagementAuthority(authentication);
		if (!this.repository.revokeApiKey(keyId)) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "API key not found");
		}
		return ResponseEntity.noContent().build();
	}

	@PostMapping("/{keyId}/rotate")
	public ResponseEntity<ApiKeyCreatedResponse> rotate(@PathVariable String keyId,
			@RequestBody(required = false) @Nullable RotateApiKeyRequest request,
			@Nullable Authentication authentication) {
		requireManagementAuthority(authentication);
		@Nullable ApiKeyEntity current = this.repository.findByKeyId(keyId);
		if (current == null) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "API key not found");
		}
		if (!this.repository.isEnabled(keyId)) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Disabled API keys cannot be rotated");
		}
		List<GrantedAuthority> authorities = request != null && request.authorities() != null
				? validateAuthorities(request.authorities()) : current.getAuthorities();
		GeneratedKey replacement = generateKey(authorities, current.getExpiresAt());
		if (!this.repository.rotateApiKey(keyId, replacement.entity())) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "API key rotation was rejected");
		}
		return ResponseEntity.status(HttpStatus.CREATED).body(replacement.response());
	}

	private ApiKeyMetadataResponse getMetadataAfterLifecycleChange(String keyId) {
		@Nullable ApiKeyEntity entity = this.repository.findByKeyId(keyId);
		if (entity == null) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "API key not found");
		}
		return metadata(entity);
	}

	private ApiKeyMetadataResponse metadata(ApiKeyEntity entity) {
		return new ApiKeyMetadataResponse(entity.getId(), this.repository.isEnabled(entity.getId()),
				entity.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList(),
				entity.getExpiresAt());
	}

	private GeneratedKey generateKey(List<GrantedAuthority> authorities, @Nullable Instant expiresAt) {
		String keyId = "mcp_" + UUID.randomUUID().toString().replace("-", "");
		byte[] secretBytes = new byte[SECRET_BYTES];
		this.secureRandom.nextBytes(secretBytes);
		String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(secretBytes);
		ApiKeyEntityImpl.Builder builder = ApiKeyEntityImpl.builder()
			.id(keyId)
			.secret(secret)
			.name("managed MCP API key")
			.authorities(authorities);
		if (expiresAt != null) {
			builder.expiresAt(expiresAt);
		}
		ApiKeyEntity entity = builder.build();
		ApiKeyCreatedResponse response = new ApiKeyCreatedResponse(keyId, secret,
				authorities.stream().map(GrantedAuthority::getAuthority).toList(), expiresAt);
		return new GeneratedKey(entity, response);
	}

	private List<GrantedAuthority> validateAuthorities(@Nullable List<String> requestedAuthorities) {
		if (requestedAuthorities == null || requestedAuthorities.isEmpty()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one authority is required");
		}
		List<String> distinctAuthorities = requestedAuthorities.stream().distinct().toList();
		if (distinctAuthorities.size() != requestedAuthorities.size()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Duplicate authorities are not allowed");
		}
		for (String authority : distinctAuthorities) {
			if (authority == null || authority.isBlank()) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Authorities must not be blank");
			}
			if (MANAGEMENT_AUTHORITY.equals(authority)) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
						"The API key management authority cannot be delegated");
			}
		}
		return distinctAuthorities.stream().map(SimpleGrantedAuthority::new).map(GrantedAuthority.class::cast)
			.toList();
	}

	private @Nullable Instant validateExpiration(@Nullable Instant expiresAt) {
		if (expiresAt != null && !expiresAt.isAfter(this.clock.instant())) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "expiresAt must be in the future");
		}
		return expiresAt;
	}

	private void requireManagementAuthority(@Nullable Authentication authentication) {
		if (authentication == null || !authentication.isAuthenticated()
				|| authentication.getAuthorities()
					.stream()
					.noneMatch(authority -> MANAGEMENT_AUTHORITY.equals(authority.getAuthority()))) {
			throw new AccessDeniedException("Missing required authority: " + MANAGEMENT_AUTHORITY);
		}
	}

	private record GeneratedKey(ApiKeyEntity entity, ApiKeyCreatedResponse response) {
	}

	public record CreateApiKeyRequest(List<String> authorities, @Nullable Instant expiresAt) {
	}

	public record RotateApiKeyRequest(@Nullable List<String> authorities) {
	}

	public record ApiKeyCreatedResponse(String keyId, String secret, List<String> authorities,
			@Nullable Instant expiresAt) {
	}

	public record ApiKeyMetadataResponse(String keyId, boolean enabled, List<String> authorities,
			@Nullable Instant expiresAt) {
	}

}
