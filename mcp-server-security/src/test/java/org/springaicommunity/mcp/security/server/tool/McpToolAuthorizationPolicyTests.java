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

import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

class McpToolAuthorizationPolicyTests {

	@Test
	void deniesUnknownToolsAndUnauthenticatedCallers() {
		var policy = new McpToolAuthorizationPolicy(Map.of("read", McpToolAuthorizationPolicy.Rule.authenticated()));
		var authenticated = authentication("SCOPE_read");

		assertThat(policy.isAllowed("unconfigured", authenticated)).isFalse();
		assertThat(policy.isAllowed("read", null)).isFalse();
		assertThat(policy.isAllowed("read", new AnonymousAuthenticationToken("key", "anonymousUser",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"))))
			.isFalse();
		assertThat(policy.isAllowed("read", UsernamePasswordAuthenticationToken.unauthenticated("user", "n/a")))
			.isFalse();
	}

	@Test
	void requiresAllConfiguredAuthoritiesByDefault() {
		var policy = new McpToolAuthorizationPolicy(
				Map.of("admin", McpToolAuthorizationPolicy.Rule.requireAll("SCOPE_read", "SCOPE_write")));

		assertThat(policy.isAllowed("admin", authentication("SCOPE_read", "SCOPE_write"))).isTrue();
		assertThat(policy.isAllowed("admin", authentication("SCOPE_read"))).isFalse();
	}

	@Test
	void supportsAnyAuthorityRules() {
		var policy = new McpToolAuthorizationPolicy(
				Map.of("lookup", McpToolAuthorizationPolicy.Rule.requireAny("SCOPE_read", "ROLE_OPERATOR")));

		assertThat(policy.isAllowed("lookup", authentication("ROLE_OPERATOR"))).isTrue();
		assertThat(policy.isAllowed("lookup", authentication("SCOPE_write"))).isFalse();
	}

	@Test
	void authenticatedRuleAllowsAnyAuthenticatedPrincipal() {
		var policy = new McpToolAuthorizationPolicy(Map.of("health", McpToolAuthorizationPolicy.Rule.authenticated()));

		assertThat(policy.isAllowed("health", authentication())).isTrue();
	}

	private UsernamePasswordAuthenticationToken authentication(String... authorities) {
		return UsernamePasswordAuthenticationToken.authenticated("user", "n/a",
				java.util.Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toList());
	}

}
