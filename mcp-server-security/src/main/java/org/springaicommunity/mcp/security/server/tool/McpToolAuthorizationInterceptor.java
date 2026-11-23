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

package org.springaicommunity.mcp.security.server.tool;

import java.util.List;
import java.util.function.Supplier;

import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import reactor.core.publisher.Mono;

/**
 * Decorates MCP SDK tool specifications with a centralized authorization policy.
 *
 * <p>
 * The supplied authentication resolver is evaluated for every invocation. For reactive
 * servers, provide a resolver that reads the authentication from the subscriber's
 * security context rather than relying on a thread-local context.
 */
public final class McpToolAuthorizationInterceptor {

	private static final String ACCESS_DENIED_MESSAGE = "Access denied";

	private McpToolAuthorizationInterceptor() {
	}

	/**
	 * Wrap a synchronous MCP tool handler.
	 * @param specification original tool specification
	 * @param policy authorization policy
	 * @param authenticationResolver resolves the current caller
	 * @return secured tool specification
	 */
	public static McpServerFeatures.SyncToolSpecification secure(McpServerFeatures.SyncToolSpecification specification,
			McpToolAuthorizationPolicy policy, Supplier<Authentication> authenticationResolver) {
		Assert.notNull(specification, "specification must not be null");
		Assert.notNull(policy, "policy must not be null");
		Assert.notNull(authenticationResolver, "authenticationResolver must not be null");
		return new McpServerFeatures.SyncToolSpecification(specification.tool(), (exchange, request) -> {
			if (!policy.isAllowed(specification.tool().name(), authenticationResolver.get())) {
				return accessDeniedResult();
			}
			return specification.callHandler().apply(exchange, request);
		});
	}

	/**
	 * Wrap an asynchronous MCP tool handler.
	 * @param specification original tool specification
	 * @param policy authorization policy
	 * @param authenticationResolver resolves the current caller at subscription time
	 * @return secured tool specification
	 */
	public static McpServerFeatures.AsyncToolSpecification secure(
			McpServerFeatures.AsyncToolSpecification specification, McpToolAuthorizationPolicy policy,
			Supplier<Authentication> authenticationResolver) {
		Assert.notNull(specification, "specification must not be null");
		Assert.notNull(policy, "policy must not be null");
		Assert.notNull(authenticationResolver, "authenticationResolver must not be null");
		return new McpServerFeatures.AsyncToolSpecification(specification.tool(),
				(exchange, request) -> Mono.defer(() -> {
					if (!policy.isAllowed(specification.tool().name(), authenticationResolver.get())) {
						return Mono.just(accessDeniedResult());
					}
					return specification.callHandler().apply(exchange, request);
				}));
	}

	private static McpSchema.CallToolResult accessDeniedResult() {
		return McpSchema.CallToolResult.builder()
			.content(List.of(McpSchema.TextContent.builder(ACCESS_DENIED_MESSAGE).build()))
			.isError(true)
			.build();
	}

}
