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
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

class McpToolAuthorizationInterceptorTests {

	@Test
	void deniesSynchronousInvocationWithoutCallingToolHandler() {
		var invoked = new AtomicBoolean();
		var original = new McpServerFeatures.SyncToolSpecification(tool(), (exchange, request) -> {
			invoked.set(true);
			return McpSchema.CallToolResult.builder().build();
		});
		var secured = McpToolAuthorizationInterceptor.secure(original, policy(), () -> null);

		var result = secured.callHandler().apply(null, null);

		assertThat(result.isError()).isTrue();
		assertThat(((McpSchema.TextContent) result.content().get(0)).text()).isEqualTo("Access denied");
		assertThat(invoked).isFalse();
	}

	@Test
	void permitsSynchronousInvocationWhenAuthorityIsGranted() {
		var invoked = new AtomicBoolean();
		var original = new McpServerFeatures.SyncToolSpecification(tool(), (exchange, request) -> {
			invoked.set(true);
			return McpSchema.CallToolResult.builder().build();
		});
		var secured = McpToolAuthorizationInterceptor.secure(original, policy(), this::authenticated);

		secured.callHandler().apply(null, null);

		assertThat(invoked).isTrue();
	}

	@Test
	void deniesAsynchronousInvocationAtSubscriptionTime() {
		var invoked = new AtomicBoolean();
		var original = new McpServerFeatures.AsyncToolSpecification(tool(),
				(exchange, request) -> reactor.core.publisher.Mono.fromSupplier(() -> {
					invoked.set(true);
					return McpSchema.CallToolResult.builder().build();
				}));
		var resolverCalls = new AtomicBoolean();
		var secured = McpToolAuthorizationInterceptor.secure(original, policy(), () -> {
			resolverCalls.set(true);
			return null;
		});

		var result = Objects.requireNonNull(secured.callHandler().apply(null, null).block());

		assertThat(resolverCalls).isTrue();
		assertThat(result.isError()).isTrue();
		assertThat(invoked).isFalse();
	}

	private McpSchema.Tool tool() {
		return McpSchema.Tool.builder("lookup", Map.of("type", "object")).build();
	}

	private McpToolAuthorizationPolicy policy() {
		return new McpToolAuthorizationPolicy(
				Map.of("lookup", McpToolAuthorizationPolicy.Rule.requireAll("SCOPE_read")));
	}

	private UsernamePasswordAuthenticationToken authenticated() {
		return UsernamePasswordAuthenticationToken.authenticated("user", "n/a",
				List.of(new SimpleGrantedAuthority("SCOPE_read")));
	}

}
