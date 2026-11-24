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

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class McpResourceAuthorizationPolicyTests {

	@Test
	void permitsExactResourceUriWithRequiredAuthority() {
		var policy = new McpResourceAuthorizationPolicy(
				Map.of("mcp://docs/readme", McpResourceAuthorizationPolicy.Rule.requireAll("SCOPE_read")));

		assertThat(policy.isAllowed("mcp://docs/readme", authenticated("SCOPE_read"))).isTrue();
		assertThat(policy.isAllowed("mcp://docs/readme", authenticated("SCOPE_write"))).isFalse();
	}

	@Test
	void matchesUriTemplateAgainstConcreteResourceUri() {
		var policy = new McpResourceAuthorizationPolicy(
				Map.of("mcp://docs/{documentId}", McpResourceAuthorizationPolicy.Rule.requireAll("SCOPE_read")));

		assertThat(policy.isAllowed("mcp://docs/guide-1", authenticated("SCOPE_read"))).isTrue();
		assertThat(policy.isAllowed("mcp://docs/guide-1", authenticated("SCOPE_write"))).isFalse();
	}

	@Test
	void deniesUnknownUrisAnonymousCallersAndAmbiguousTemplates() {
		var policy = new McpResourceAuthorizationPolicy(
				Map.of("mcp://docs/{documentId}", McpResourceAuthorizationPolicy.Rule.authenticated(),
						"mcp://{category}/guide", McpResourceAuthorizationPolicy.Rule.authenticated()));

		assertThat(policy.isAllowed("mcp://docs/guide", authenticated("SCOPE_read"))).isFalse();
		assertThat(policy.isAllowed("mcp://other/resource", authenticated("SCOPE_read"))).isFalse();
		assertThat(policy.isAllowed("mcp://docs/guide", null)).isFalse();
	}

	@Test
	void exactUriRuleTakesPrecedenceOverMatchingTemplate() {
		var policy = new McpResourceAuthorizationPolicy(
				Map.of("mcp://docs/{documentId}", McpResourceAuthorizationPolicy.Rule.authenticated(),
						"mcp://docs/private", McpResourceAuthorizationPolicy.Rule.requireAll("SCOPE_admin")));

		assertThat(policy.isAllowed("mcp://docs/private", authenticated("SCOPE_read"))).isFalse();
		assertThat(policy.isAllowed("mcp://docs/public", authenticated("SCOPE_read"))).isTrue();
	}

	private Authentication authenticated(String... authorities) {
		return UsernamePasswordAuthenticationToken.authenticated("resource-user", "n/a",
				Set.of(authorities).stream().map(SimpleGrantedAuthority::new).toList());
	}

}

class McpResourceAuthorizationInterceptorTests {

	@Test
	void deniesSynchronousResourceReadWithoutCallingHandler() {
		var invoked = new AtomicBoolean();
		var resource = McpSchema.Resource.builder("mcp://docs/readme", "readme").build();
		var original = new McpServerFeatures.SyncResourceSpecification(resource, (exchange, request) -> {
			invoked.set(true);
			return McpSchema.ReadResourceResult.builder(List.of()).build();
		});
		var policy = new McpResourceAuthorizationPolicy(
				Map.of("mcp://docs/readme", McpResourceAuthorizationPolicy.Rule.requireAll("SCOPE_read")));
		var secured = McpResourceAuthorizationInterceptor.secure(original, policy, () -> null);

		assertThatThrownBy(
				() -> secured.readHandler().apply(null, new McpSchema.ReadResourceRequest("mcp://docs/readme")))
			.isInstanceOf(McpError.class)
			.satisfies(error -> assertThat(((McpError) error).getJsonRpcError().code())
				.isEqualTo(McpSchema.ErrorCodes.RESOURCE_NOT_FOUND));
		assertThat(invoked).isFalse();
	}

	@Test
	void permitsSynchronousResourceTemplateReadUsingConcreteUri() {
		var invoked = new AtomicBoolean();
		var template = McpSchema.ResourceTemplate.builder("mcp://docs/{documentId}", "documents").build();
		var original = new McpServerFeatures.SyncResourceTemplateSpecification(template, (exchange, request) -> {
			invoked.set(true);
			return McpSchema.ReadResourceResult.builder(List.of()).build();
		});
		var policy = new McpResourceAuthorizationPolicy(
				Map.of("mcp://docs/{documentId}", McpResourceAuthorizationPolicy.Rule.requireAll("SCOPE_read")));
		var secured = McpResourceAuthorizationInterceptor.secure(original, policy, () -> authenticated());

		secured.readHandler().apply(null, new McpSchema.ReadResourceRequest("mcp://docs/guide-1"));

		assertThat(invoked).isTrue();
	}

	@Test
	void deniesAsynchronousResourceReadAtSubscriptionTime() {
		var invoked = new AtomicBoolean();
		var resolverCalled = new AtomicBoolean();
		var resource = McpSchema.Resource.builder("mcp://docs/readme", "readme").build();
		var original = new McpServerFeatures.AsyncResourceSpecification(resource,
				(exchange, request) -> reactor.core.publisher.Mono.fromSupplier(() -> {
					invoked.set(true);
					return McpSchema.ReadResourceResult.builder(List.of()).build();
				}));
		var policy = new McpResourceAuthorizationPolicy(
				Map.of("mcp://docs/readme", McpResourceAuthorizationPolicy.Rule.authenticated()));
		var secured = McpResourceAuthorizationInterceptor.secure(original, policy, () -> {
			resolverCalled.set(true);
			return null;
		});

		assertThatThrownBy(
				() -> secured.readHandler().apply(null, new McpSchema.ReadResourceRequest("mcp://docs/readme")).block())
			.isInstanceOf(McpError.class);
		assertThat(resolverCalled).isTrue();
		assertThat(invoked).isFalse();
	}

	@Test
	void permitsAsynchronousResourceTemplateReadAtSubscriptionTime() {
		var invoked = new AtomicBoolean();
		var template = McpSchema.ResourceTemplate.builder("mcp://docs/{documentId}", "documents").build();
		var original = new McpServerFeatures.AsyncResourceTemplateSpecification(template,
				(exchange, request) -> reactor.core.publisher.Mono.fromSupplier(() -> {
					invoked.set(true);
					return McpSchema.ReadResourceResult.builder(List.of()).build();
				}));
		var policy = new McpResourceAuthorizationPolicy(
				Map.of("mcp://docs/{documentId}", McpResourceAuthorizationPolicy.Rule.requireAll("SCOPE_read")));
		var secured = McpResourceAuthorizationInterceptor.secure(original, policy, () -> authenticated());

		secured.readHandler().apply(null, new McpSchema.ReadResourceRequest("mcp://docs/guide-1")).block();

		assertThat(invoked).isTrue();
	}

	private Authentication authenticated() {
		return UsernamePasswordAuthenticationToken.authenticated("resource-user", "n/a",
				List.of(new SimpleGrantedAuthority("SCOPE_read")));
	}

}
