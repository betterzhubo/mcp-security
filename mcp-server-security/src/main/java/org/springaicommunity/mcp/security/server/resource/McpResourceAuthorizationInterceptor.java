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

package org.springaicommunity.mcp.security.server.resource;

import java.util.function.Supplier;

import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import reactor.core.publisher.Mono;

/**
 * Decorates MCP SDK resource and resource-template specifications with a centralized
 * authorization policy.
 *
 * <p>
 * The authentication resolver is evaluated for every read request. For asynchronous
 * servers, it is evaluated at subscription time so reactive security contexts can be
 * resolved correctly.
 */
public final class McpResourceAuthorizationInterceptor {

	private static final String ACCESS_DENIED_MESSAGE = "Resource not found";

	private McpResourceAuthorizationInterceptor() {
	}

	/**
	 * Wrap a synchronous resource handler.
	 * @param specification original resource specification
	 * @param policy resource authorization policy
	 * @param authenticationResolver resolves the current caller
	 * @return secured resource specification
	 */
	public static McpServerFeatures.SyncResourceSpecification secure(
			McpServerFeatures.SyncResourceSpecification specification, McpResourceAuthorizationPolicy policy,
			Supplier<@Nullable Authentication> authenticationResolver) {
		Assert.notNull(specification, "specification must not be null");
		Assert.notNull(policy, "policy must not be null");
		Assert.notNull(authenticationResolver, "authenticationResolver must not be null");
		return new McpServerFeatures.SyncResourceSpecification(specification.resource(), (exchange, request) -> {
			Authentication authentication = authenticationResolver.get();
			if (!policy.isAllowed(request.uri(), authentication)) {
				throw accessDenied();
			}
			return specification.readHandler().apply(exchange, request);
		});
	}

	/**
	 * Wrap an asynchronous resource handler.
	 * @param specification original resource specification
	 * @param policy resource authorization policy
	 * @param authenticationResolver resolves the current caller at subscription time
	 * @return secured resource specification
	 */
	public static McpServerFeatures.AsyncResourceSpecification secure(
			McpServerFeatures.AsyncResourceSpecification specification, McpResourceAuthorizationPolicy policy,
			Supplier<@Nullable Authentication> authenticationResolver) {
		Assert.notNull(specification, "specification must not be null");
		Assert.notNull(policy, "policy must not be null");
		Assert.notNull(authenticationResolver, "authenticationResolver must not be null");
		return new McpServerFeatures.AsyncResourceSpecification(specification.resource(),
				(exchange, request) -> Mono.defer(() -> {
					Authentication authentication = authenticationResolver.get();
					if (!policy.isAllowed(request.uri(), authentication)) {
						return Mono.<McpSchema.ReadResourceResult>error(accessDenied());
					}
					return specification.readHandler().apply(exchange, request);
				}));
	}

	/**
	 * Wrap a synchronous resource-template handler. The policy is evaluated against the
	 * concrete URI from each read request, not the template declaration.
	 * @param specification original resource-template specification
	 * @param policy resource authorization policy
	 * @param authenticationResolver resolves the current caller
	 * @return secured resource-template specification
	 */
	public static McpServerFeatures.SyncResourceTemplateSpecification secure(
			McpServerFeatures.SyncResourceTemplateSpecification specification, McpResourceAuthorizationPolicy policy,
			Supplier<@Nullable Authentication> authenticationResolver) {
		Assert.notNull(specification, "specification must not be null");
		Assert.notNull(policy, "policy must not be null");
		Assert.notNull(authenticationResolver, "authenticationResolver must not be null");
		return new McpServerFeatures.SyncResourceTemplateSpecification(specification.resourceTemplate(),
				(exchange, request) -> {
					Authentication authentication = authenticationResolver.get();
					if (!policy.isAllowed(request.uri(), authentication)) {
						throw accessDenied();
					}
					return specification.readHandler().apply(exchange, request);
				});
	}

	/**
	 * Wrap an asynchronous resource-template handler. The policy is evaluated against the
	 * concrete URI from each read request, at subscription time.
	 * @param specification original resource-template specification
	 * @param policy resource authorization policy
	 * @param authenticationResolver resolves the current caller at subscription time
	 * @return secured resource-template specification
	 */
	public static McpServerFeatures.AsyncResourceTemplateSpecification secure(
			McpServerFeatures.AsyncResourceTemplateSpecification specification, McpResourceAuthorizationPolicy policy,
			Supplier<@Nullable Authentication> authenticationResolver) {
		Assert.notNull(specification, "specification must not be null");
		Assert.notNull(policy, "policy must not be null");
		Assert.notNull(authenticationResolver, "authenticationResolver must not be null");
		return new McpServerFeatures.AsyncResourceTemplateSpecification(specification.resourceTemplate(),
				(exchange, request) -> Mono.defer(() -> {
					Authentication authentication = authenticationResolver.get();
					if (!policy.isAllowed(request.uri(), authentication)) {
						return Mono.error(accessDenied());
					}
					return specification.readHandler().apply(exchange, request);
				}));
	}

	private static McpError accessDenied() {
		// Use RESOURCE_NOT_FOUND to avoid disclosing whether a protected resource exists.
		return McpError.builder(McpSchema.ErrorCodes.RESOURCE_NOT_FOUND).message(ACCESS_DENIED_MESSAGE).build();
	}

}
