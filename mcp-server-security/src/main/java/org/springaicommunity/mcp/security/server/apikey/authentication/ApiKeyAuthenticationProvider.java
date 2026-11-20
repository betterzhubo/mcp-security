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

	private PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

	public ApiKeyAuthenticationProvider(ApiKeyEntityRepository<T> apiKeyEntityRepository) {
		this(apiKeyEntityRepository, Clock.systemUTC());
	}

	/**
	 * Create an authentication provider using the supplied clock.
	 * @param apiKeyEntityRepository repository used to look up API keys
	 * @param clock clock used to evaluate API key expiration
	 */
	public ApiKeyAuthenticationProvider(ApiKeyEntityRepository<T> apiKeyEntityRepository, Clock clock) {
		Assert.notNull(apiKeyEntityRepository, "apiKeyRepository cannot be null");
		Assert.notNull(clock, "clock cannot be null");
		this.apiKeyEntityRepository = apiKeyEntityRepository;
		this.clock = clock;
	}

	@Override
	public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}

		ApiKeyAuthenticationToken apiKeyToken = (ApiKeyAuthenticationToken) authentication;
		var apiKey = apiKeyToken.getCredentials();

		if (apiKey == null) {
			throw new BadCredentialsException("API key is null");
		}

		T loggedInEntity = this.apiKeyEntityRepository.findByKeyId(apiKey.getId());
		if (loggedInEntity == null) {
			throw new BadCredentialsException("Invalid API key");
		}
		if (!passwordEncoder.matches(apiKey.getSecret(), loggedInEntity.getSecret())) {
			throw new BadCredentialsException("API key does not match");
		}
		if (loggedInEntity.getExpiresAt() != null && !this.clock.instant().isBefore(loggedInEntity.getExpiresAt())) {
			throw new BadCredentialsException("API key has expired");
		}

		return ApiKeyAuthenticationToken.authenticated(loggedInEntity, loggedInEntity.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return ApiKeyAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

}
