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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.springaicommunity.mcp.security.server.tool.audit.McpToolAuditEvent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class McpToolAuthorizationAuditTests {

	private final McpToolAuthorizationPolicy policy = new McpToolAuthorizationPolicy(
			Map.of("lookup", McpToolAuthorizationPolicy.Rule.requireAll("SCOPE_read")));

	@Test
	void recordsDeniedSynchronousInvocationWithoutCallingHandler() {
		var events = new ArrayList<McpToolAuditEvent>();
		var invoked = new AtomicBoolean();
		var original = syncTool((exchange, request) -> {
			invoked.set(true);
			return successResult();
		});

		var secured = McpToolAuthorizationInterceptor.secure(original, policy, () -> null, events::add);
		var result = secured.callHandler().apply(null, null);

		assertThat(result.isError()).isTrue();
		assertThat(invoked).isFalse();
		assertThat(events).singleElement().satisfies(event -> {
			assertThat(event.toolName()).isEqualTo("lookup");
			assertThat(event.caller()).isNull();
			assertThat(event.outcome()).isEqualTo(McpToolAuditEvent.Outcome.DENIED);
			assertThat(event.reason()).isEqualTo(McpToolAuditEvent.Reason.AUTHORIZATION_DENIED);
			assertThat(event.durationMillis()).isGreaterThanOrEqualTo(0);
		});
	}

	@Test
	void recordsSuccessfulSynchronousInvocation() {
		var events = new ArrayList<McpToolAuditEvent>();
		var secured = McpToolAuthorizationInterceptor.secure(syncTool((exchange, request) -> successResult()), policy,
				this::authenticated, events::add);

		secured.callHandler().apply(null, null);

		assertThat(events).singleElement().satisfies(event -> {
			assertThat(event.toolName()).isEqualTo("lookup");
			assertThat(event.caller()).isEqualTo("audit-user");
			assertThat(event.outcome()).isEqualTo(McpToolAuditEvent.Outcome.SUCCESS);
			assertThat(event.reason()).isEqualTo(McpToolAuditEvent.Reason.NONE);
		});
	}

	@Test
	void recordsHandlerFailureAndRethrowsWithoutExceptionDetails() {
		var events = new ArrayList<McpToolAuditEvent>();
		var secured = McpToolAuthorizationInterceptor.secure(syncTool((exchange, request) -> {
			throw new IllegalStateException("do-not-record-this-message");
		}), policy, this::authenticated, events::add);

		assertThatThrownBy(() -> secured.callHandler().apply(null, null)).isInstanceOf(IllegalStateException.class)
			.hasMessage("do-not-record-this-message");
		assertThat(events).singleElement().satisfies(event -> {
			assertThat(event.outcome()).isEqualTo(McpToolAuditEvent.Outcome.FAILURE);
			assertThat(event.reason()).isEqualTo(McpToolAuditEvent.Reason.HANDLER_EXCEPTION);
			assertThat(event.toString()).doesNotContain("do-not-record-this-message");
		});
	}

	@Test
	void recordsAsynchronousInvocationAtSubscriptionTime() {
		var events = new ArrayList<McpToolAuditEvent>();
		var resolverCalls = new AtomicBoolean();
		var original = new McpServerFeatures.AsyncToolSpecification(tool(),
				(exchange, request) -> reactor.core.publisher.Mono.just(successResult()));
		var secured = McpToolAuthorizationInterceptor.secure(original, policy, () -> {
			resolverCalls.set(true);
			return authenticated();
		}, events::add);

		Objects.requireNonNull(secured.callHandler().apply(null, null).block());

		assertThat(resolverCalls).isTrue();
		assertThat(events).singleElement().satisfies(event -> {
			assertThat(event.outcome()).isEqualTo(McpToolAuditEvent.Outcome.SUCCESS);
			assertThat(event.caller()).isEqualTo("audit-user");
		});
	}

	@Test
	void auditSinkFailureDoesNotInterruptToolExecution() {
		var invoked = new AtomicBoolean();
		var secured = McpToolAuthorizationInterceptor.secure(syncTool((exchange, request) -> {
			invoked.set(true);
			return successResult();
		}), policy, this::authenticated, event -> {
			throw new IllegalStateException("sensitive-sink-error");
		});

		secured.callHandler().apply(null, null);

		assertThat(invoked).isTrue();
	}

	private McpServerFeatures.SyncToolSpecification syncTool(
			java.util.function.BiFunction<io.modelcontextprotocol.server.McpSyncServerExchange, McpSchema.CallToolRequest, McpSchema.CallToolResult> handler) {
		return new McpServerFeatures.SyncToolSpecification(tool(), handler);
	}

	private McpSchema.Tool tool() {
		return McpSchema.Tool.builder("lookup", Map.of("type", "object")).build();
	}

	private McpSchema.CallToolResult successResult() {
		return McpSchema.CallToolResult.builder().build();
	}

	private Authentication authenticated() {
		return UsernamePasswordAuthenticationToken.authenticated("audit-user", "n/a",
				List.of(new SimpleGrantedAuthority("SCOPE_read")));
	}

}
