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

package org.springaicommunity.mcp.security.server.apikey.authentication;

import java.time.Clock;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;
import org.springaicommunity.mcp.security.server.apikey.audit.ApiKeyAuditEvent;
import org.springaicommunity.mcp.security.server.apikey.audit.ApiKeyAuditLogger;
import org.springaicommunity.mcp.security.server.apikey.audit.DefaultApiKeyAuditLogger;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityLifecycleRepository;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityRepository;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

/**
 * {@link AuthenticationProvider} that validates an API key against a configured
 * {@link ApiKeyEntityRepository}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class ApiKeyAuthenticationProvider<T extends ApiKeyEntity> implements AuthenticationProvider {

	private final ApiKeyEntityRepository<T> apiKeyEntityRepository;

	private final Clock clock;

	private final ApiKeyAuditLogger auditLogger;

	private PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

	public ApiKeyAuthenticationProvider(ApiKeyEntityRepository<T> apiKeyEntityRepository) {
		this(apiKeyEntityRepository, Clock.systemUTC(), new DefaultApiKeyAuditLogger());
	}

	/**
	 * Create an authentication provider using the supplied clock.
	 * @param apiKeyEntityRepository repository used to look up API keys
	 * @param clock clock used to evaluate API key expiration
	 */
	public ApiKeyAuthenticationProvider(ApiKeyEntityRepository<T> apiKeyEntityRepository, Clock clock) {
		this(apiKeyEntityRepository, clock, new DefaultApiKeyAuditLogger());
	}

	/**
	 * Create an authentication provider with a configurable audit sink.
	 * @param apiKeyEntityRepository repository used to look up API keys
	 * @param clock clock used to evaluate API key expiration and timestamp audit events
	 * @param auditLogger receives sanitized authentication audit events
	 */
	public ApiKeyAuthenticationProvider(ApiKeyEntityRepository<T> apiKeyEntityRepository, Clock clock,
			ApiKeyAuditLogger auditLogger) {
		Assert.notNull(apiKeyEntityRepository, "apiKeyRepository cannot be null");
		Assert.notNull(clock, "clock cannot be null");
		Assert.notNull(auditLogger, "auditLogger cannot be null");
		this.apiKeyEntityRepository = apiKeyEntityRepository;
		this.clock = clock;
		this.auditLogger = auditLogger;
	}

	@Override
	public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}

		ApiKeyAuthenticationToken apiKeyToken = (ApiKeyAuthenticationToken) authentication;
		var apiKey = apiKeyToken.getCredentials();
		if (apiKey == null) {
			reject(null, ApiKeyAuditEvent.Reason.MISSING_CREDENTIALS, "API key is null");
		}

		String keyId = apiKey.getId();
		T loggedInEntity = this.apiKeyEntityRepository.findByKeyId(keyId);
		if (loggedInEntity == null) {
			reject(keyId, ApiKeyAuditEvent.Reason.KEY_NOT_FOUND, "Invalid API key");
		}
		if (this.apiKeyEntityRepository instanceof ApiKeyEntityLifecycleRepository<?> lifecycleRepository
				&& !lifecycleRepository.isEnabled(keyId)) {
			reject(keyId, ApiKeyAuditEvent.Reason.KEY_DISABLED, "Invalid API key");
		}
		if (!passwordEncoder.matches(apiKey.getSecret(), loggedInEntity.getSecret())) {
			reject(keyId, ApiKeyAuditEvent.Reason.SECRET_MISMATCH, "API key does not match");
		}
		if (loggedInEntity.getExpiresAt() != null && !this.clock.instant().isBefore(loggedInEntity.getExpiresAt())) {
			reject(keyId, ApiKeyAuditEvent.Reason.KEY_EXPIRED, "API key has expired");
		}

		audit(keyId, ApiKeyAuditEvent.Outcome.SUCCESS, ApiKeyAuditEvent.Reason.NONE);
		return ApiKeyAuthenticationToken.authenticated(loggedInEntity, loggedInEntity.getAuthorities());
	}

	private void reject(@Nullable String keyId, ApiKeyAuditEvent.Reason reason, String message) {
		audit(keyId, ApiKeyAuditEvent.Outcome.FAILURE, reason);
		throw new BadCredentialsException(message);
	}

	private void audit(@Nullable String keyId, ApiKeyAuditEvent.Outcome outcome, ApiKeyAuditEvent.Reason reason) {
		this.auditLogger.logSafely(new ApiKeyAuditEvent(this.clock.instant(), ApiKeyAuditEvent.Action.AUTHENTICATE,
				keyId, outcome, reason));
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return ApiKeyAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

}
