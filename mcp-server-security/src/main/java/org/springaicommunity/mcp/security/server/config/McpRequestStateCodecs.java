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

package org.springaicommunity.mcp.security.server.config;

import java.time.Duration;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.modern.server.HmacRequestStateCodec;
import io.modelcontextprotocol.modern.server.RequestStateCodec;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Factory methods for MRTR request-state codecs integrated with Spring Security.
 *
 * <p>The returned codec binds each sealed request state to the name of the authenticated
 * Spring Security principal. It fails closed when no authenticated, non-anonymous
 * principal is present. The codec also retains the SDK's HMAC integrity check, expiry,
 * method binding, and primitive binding.
 *
 * <p>Use this with the modern MCP server builder:
 *
 * <pre>
 * RequestStateCodec codec = McpRequestStateCodecs.springSecurity(signingKey);
 * McpServer server = McpServer.builder()
 *     .requestStateCodec(codec)
 *     // configure features
 *     .build();
 * </pre>
 *
 * <p>The principal is read from {@link SecurityContextHolder} when the SDK seals or opens
 * state. This is suitable when the MCP request is dispatched on a thread carrying the
 * Spring Security context, such as the SDK's blocking {@code HttpServletMcpTransport}.
 * Reactive or custom transports must explicitly propagate the security context to the
 * dispatch thread; otherwise this factory rejects the request.
 *
 * @author OpenAI
 */
public final class McpRequestStateCodecs {

	private static final Duration DEFAULT_TTL = Duration.ofMinutes(10);

	private static final AuthenticationTrustResolver TRUST_RESOLVER = new AuthenticationTrustResolverImpl();

	private McpRequestStateCodecs() {
	}

	/**
	 * Create an HMAC-SHA256 request-state codec bound to the current authenticated
	 * Spring Security principal, with a ten-minute time-to-live.
	 * @param key the shared HMAC signing key; must contain at least 32 bytes
	 * @return the configured request-state codec
	 */
	public static RequestStateCodec springSecurity(byte[] key) {
		return springSecurity(key, DEFAULT_TTL);
	}

	/**
	 * Create an HMAC-SHA256 request-state codec bound to the current authenticated
	 * Spring Security principal.
	 * @param key the shared HMAC signing key; must contain at least 32 bytes
	 * @param ttl the maximum age of a sealed request state; must be positive
	 * @return the configured request-state codec
	 */
	public static RequestStateCodec springSecurity(byte[] key, Duration ttl) {
		Assert.notNull(key, "key must not be null");
		Assert.isTrue(key.length >= 32, "key must contain at least 32 bytes");
		Assert.notNull(ttl, "ttl must not be null");
		Assert.isTrue(!ttl.isNegative() && !ttl.isZero(), "ttl must be positive");

		return HmacRequestStateCodec.builder()
			.key(key.clone())
			.ttl(ttl)
			.principalExtractor(McpRequestStateCodecs::authenticatedPrincipal)
			.build();
	}

	private static String authenticatedPrincipal(McpTransportContext transportContext) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !authentication.isAuthenticated()
				|| TRUST_RESOLVER.isAnonymous(authentication)) {
			throw new IllegalStateException("An authenticated principal is required for MRTR requestState");
		}
		String principal = authentication.getName();
		if (!StringUtils.hasText(principal)) {
			throw new IllegalStateException("The authenticated principal must have a non-empty name");
		}
		return principal;
	}

}
