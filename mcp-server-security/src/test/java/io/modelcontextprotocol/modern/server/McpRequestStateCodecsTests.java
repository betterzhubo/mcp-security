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

package io.modelcontextprotocol.modern.server;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.modern.McpSchema;
import io.modelcontextprotocol.modern.McpSchema.ClientCapabilities;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.config.McpRequestStateCodecs;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class McpRequestStateCodecsTests {

	private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes();

	private static McpRequestContext context() {
		return new McpRequestContext(1, "tools/call", McpSchema.LATEST_PROTOCOL_VERSION, ClientCapabilities.NONE, null,
				null, "echo", Map.of(), McpTransportContext.EMPTY, false, false);
	}

	@AfterEach
	void clearSecurityContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void bindsRequestStateToAuthenticatedPrincipal() {
		var codec = McpRequestStateCodecs.springSecurity(KEY);
		SecurityContextHolder.getContext()
			.setAuthentication(UsernamePasswordAuthenticationToken.authenticated("alice", "n/a", List.of()));

		String sealed = codec.seal(context(), "state");

		SecurityContextHolder.getContext()
			.setAuthentication(UsernamePasswordAuthenticationToken.authenticated("bob", "n/a", List.of()));
		assertThat(codec.open(context(), sealed)).isNull();

		SecurityContextHolder.getContext()
			.setAuthentication(UsernamePasswordAuthenticationToken.authenticated("alice", "n/a", List.of()));
		assertThat(codec.open(context(), sealed)).isEqualTo("state");
	}

	@Test
	void rejectsMissingAuthentication() {
		var codec = McpRequestStateCodecs.springSecurity(KEY);

		assertThatThrownBy(() -> codec.seal(context(), "state")).isInstanceOf(IllegalStateException.class)
			.hasMessage("An authenticated principal is required for MRTR requestState");
	}

	@Test
	void rejectsAnonymousAuthentication() {
		var codec = McpRequestStateCodecs.springSecurity(KEY);
		SecurityContextHolder.getContext()
			.setAuthentication(
					new AnonymousAuthenticationToken("key", "anonymousUser", List.of(() -> "ROLE_ANONYMOUS")));

		assertThatThrownBy(() -> codec.seal(context(), "state")).isInstanceOf(IllegalStateException.class)
			.hasMessage("An authenticated principal is required for MRTR requestState");
	}

	@Test
	void validatesSigningKeyAndTtl() {
		assertThatThrownBy(() -> McpRequestStateCodecs.springSecurity(new byte[31]))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("key must contain at least 32 bytes");
		assertThatThrownBy(() -> McpRequestStateCodecs.springSecurity(KEY, Duration.ZERO))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("ttl must be positive");
	}

}
