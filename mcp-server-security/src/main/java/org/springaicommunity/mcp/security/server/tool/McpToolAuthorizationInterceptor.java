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

import java.time.Clock;
import java.util.List;
import java.util.function.Supplier;

import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import org.springaicommunity.mcp.security.server.tool.audit.McpToolAuditEvent;
import org.springaicommunity.mcp.security.server.tool.audit.McpToolAuditLogger;

import reactor.core.publisher.Mono;

/**
 * Decorates MCP SDK tool specifications with a centralized authorization policy and,
 * optionally, invocation auditing.
 *
 * <p>The supplied authentication resolver is evaluated for every invocation. For reactive
 * servers, provide a resolver that reads the authentication from the subscriber's security
 * context rather than relying on a thread-local context.
 *
 * <p>Auditing is opt-in through the overloads that accept a {@link McpToolAuditLogger}.
 * Only the tool name, authenticated principal name, outcome, stable reason code, timestamp,
 * and elapsed time are recorded. Tool arguments, results, credentials, and exception
 * messages are never passed to the audit logger.
 */
public final class McpToolAuthorizationInterceptor {

	private static final String ACCESS_DENIED_MESSAGE = "Access denied";

	private McpToolAuthorizationInterceptor() {
	}

	/**
	 * Wrap a synchronous MCP tool handler without invocation auditing.
	 * @param specification original tool specification
	 * @param policy authorization policy
	 * @param authenticationResolver resolves the current caller
	 * @return secured tool specification
	 */
	public static McpServerFeatures.SyncToolSpecification secure(McpServerFeatures.SyncToolSpecification specification,
			McpToolAuthorizationPolicy policy, Supplier<@Nullable Authentication> authenticationResolver) {
		return secure(specification, policy, authenticationResolver, event -> { }, Clock.systemUTC());
	}

	/**
	 * Wrap a synchronous MCP tool handler with invocation auditing.
	 * @param specification original tool specification
	 * @param policy authorization policy
	 * @param authenticationResolver resolves the current caller
	 * @param auditLogger receives sanitized invocation events
	 * @return secured tool specification
	 */
	public static McpServerFeatures.SyncToolSpecification secure(McpServerFeatures.SyncToolSpecification specification,
			McpToolAuthorizationPolicy policy, Supplier<@Nullable Authentication> authenticationResolver,
			McpToolAuditLogger auditLogger) {
		return secure(specification, policy, authenticationResolver, auditLogger, Clock.systemUTC());
	}

	static McpServerFeatures.SyncToolSpecification secure(McpServerFeatures.SyncToolSpecification specification,
			McpToolAuthorizationPolicy policy, Supplier<@Nullable Authentication> authenticationResolver,
			McpToolAuditLogger auditLogger, Clock clock) {
		Assert.notNull(specification, "specification must not be null");
		Assert.notNull(policy, "policy must not be null");
		Assert.notNull(authenticationResolver, "authenticationResolver must not be null");
		Assert.notNull(auditLogger, "auditLogger must not be null");
		Assert.notNull(clock, "clock must not be null");
		return new McpServerFeatures.SyncToolSpecification(specification.tool(), (exchange, request) -> {
			long startedAt = System.nanoTime();
			Authentication authentication = authenticationResolver.get();
			String toolName = specification.tool().name();
			if (!policy.isAllowed(toolName, authentication)) {
				log(auditLogger, clock, toolName, authentication, McpToolAuditEvent.Outcome.DENIED,
						McpToolAuditEvent.Reason.AUTHORIZATION_DENIED, startedAt);
				return accessDeniedResult();
			}
			try {
				McpSchema.CallToolResult result = specification.callHandler().apply(exchange, request);
				boolean toolError = result.isError();
				log(auditLogger, clock, toolName, authentication,
						toolError ? McpToolAuditEvent.Outcome.FAILURE : McpToolAuditEvent.Outcome.SUCCESS,
						toolError ? McpToolAuditEvent.Reason.TOOL_ERROR_RESULT : McpToolAuditEvent.Reason.NONE,
						startedAt);
				return result;
			}
			catch (RuntimeException | Error ex) {
				log(auditLogger, clock, toolName, authentication, McpToolAuditEvent.Outcome.FAILURE,
						McpToolAuditEvent.Reason.HANDLER_EXCEPTION, startedAt);
				throw ex;
			}
		});
	}

	/**
	 * Wrap an asynchronous MCP tool handler without invocation auditing.
	 * @param specification original tool specification
	 * @param policy authorization policy
	 * @param authenticationResolver resolves the current caller at subscription time
	 * @return secured tool specification
	 */
	public static McpServerFeatures.AsyncToolSpecification secure(
			McpServerFeatures.AsyncToolSpecification specification, McpToolAuthorizationPolicy policy,
			Supplier<Authentication> authenticationResolver) {
		return secure(specification, policy, authenticationResolver, event -> { }, Clock.systemUTC());
	}

	/**
	 * Wrap an asynchronous MCP tool handler with invocation auditing.
	 * @param specification original tool specification
	 * @param policy authorization policy
	 * @param authenticationResolver resolves the current caller at subscription time
	 * @param auditLogger receives sanitized invocation events
	 * @return secured tool specification
	 */
	public static McpServerFeatures.AsyncToolSpecification secure(
			McpServerFeatures.AsyncToolSpecification specification, McpToolAuthorizationPolicy policy,
			Supplier<Authentication> authenticationResolver, McpToolAuditLogger auditLogger) {
		return secure(specification, policy, authenticationResolver, auditLogger, Clock.systemUTC());
	}

	static McpServerFeatures.AsyncToolSpecification secure(
			McpServerFeatures.AsyncToolSpecification specification, McpToolAuthorizationPolicy policy,
			Supplier<Authentication> authenticationResolver, McpToolAuditLogger auditLogger, Clock clock) {
		Assert.notNull(specification, "specification must not be null");
		Assert.notNull(policy, "policy must not be null");
		Assert.notNull(authenticationResolver, "authenticationResolver must not be null");
		Assert.notNull(auditLogger, "auditLogger must not be null");
		Assert.notNull(clock, "clock must not be null");
		return new McpServerFeatures.AsyncToolSpecification(specification.tool(), (exchange, request) -> Mono.defer(() -> {
			long startedAt = System.nanoTime();
			Authentication authentication = authenticationResolver.get();
			String toolName = specification.tool().name();
			if (!policy.isAllowed(toolName, authentication)) {
				log(auditLogger, clock, toolName, authentication, McpToolAuditEvent.Outcome.DENIED,
						McpToolAuditEvent.Reason.AUTHORIZATION_DENIED, startedAt);
				return Mono.just(accessDeniedResult());
			}
			return specification.callHandler().apply(exchange, request)
				.doOnNext(result -> log(auditLogger, clock, toolName, authentication,
						result.isError() ? McpToolAuditEvent.Outcome.FAILURE : McpToolAuditEvent.Outcome.SUCCESS,
						result.isError() ? McpToolAuditEvent.Reason.TOOL_ERROR_RESULT : McpToolAuditEvent.Reason.NONE,
						startedAt))
				.doOnError(error -> log(auditLogger, clock, toolName, authentication,
						McpToolAuditEvent.Outcome.FAILURE, McpToolAuditEvent.Reason.HANDLER_EXCEPTION, startedAt));
		}));
	}

	private static void log(McpToolAuditLogger auditLogger, Clock clock, String toolName,
			@Nullable Authentication authentication, McpToolAuditEvent.Outcome outcome,
			McpToolAuditEvent.Reason reason, long startedAt) {
		String caller = authentication == null ? null : authentication.getName();
		long durationMillis = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
		auditLogger.logSafely(new McpToolAuditEvent(clock.instant(), toolName, caller, outcome, reason, durationMillis));
	}

	private static McpSchema.CallToolResult accessDeniedResult() {
		return McpSchema.CallToolResult.builder()
			.content(List.of(McpSchema.TextContent.builder(ACCESS_DENIED_MESSAGE).build()))
			.isError(true)
			.build();
	}

}
