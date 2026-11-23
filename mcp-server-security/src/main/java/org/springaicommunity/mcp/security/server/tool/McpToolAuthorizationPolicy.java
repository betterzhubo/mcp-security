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
import java.util.Set;

import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Immutable authorization policy for MCP tools.
 *
 * <p>Tools without an explicit rule are denied by default. A rule with no required
 * authorities permits any authenticated principal; use this only for tools that are
 * intentionally available to every authenticated caller.
 */
public final class McpToolAuthorizationPolicy {

	private final Map<String, Rule> rules;

	public McpToolAuthorizationPolicy(Map<String, Rule> rules) {
		Assert.notNull(rules, "rules must not be null");
		Assert.noNullElements(rules.keySet(), "tool names must not contain null");
		Assert.noNullElements(rules.values(), "rules must not contain null");
		this.rules = Map.copyOf(rules);
	}

	/**
	 * Determine whether an authenticated principal satisfies the configured rule.
	 * @param toolName MCP tool name
	 * @param authentication current authenticated principal
	 * @return {@code true} only when an explicit rule exists and is satisfied
	 */
	public boolean isAllowed(String toolName, Authentication authentication) {
		Assert.hasText(toolName, "toolName must not be empty");
		if (authentication == null || !authentication.isAuthenticated()
				|| new AuthenticationTrustResolverImpl().isAnonymous(authentication)) {
			return false;
		}
		Rule rule = this.rules.get(toolName);
		if (rule == null) {
			return false;
		}
		if (rule.requiredAuthorities().isEmpty()) {
			return true;
		}
		Set<String> granted = authentication.getAuthorities()
			.stream()
			.map(authority -> authority.getAuthority())
			.collect(java.util.stream.Collectors.toUnmodifiableSet());
		return rule.match() == Match.ALL
				? granted.containsAll(rule.requiredAuthorities())
				: rule.requiredAuthorities().stream().anyMatch(granted::contains);
	}

	public enum Match {

		ALL, ANY

	}

	/**
	 * Required authorities and their matching semantics for one tool.
	 * An empty authority set means authenticated-only access.
	 * @param requiredAuthorities authorities required by the rule
	 * @param match whether all or at least one authority must be present
	 */
	public record Rule(Set<String> requiredAuthorities, Match match) {

		public Rule {
			Assert.notNull(requiredAuthorities, "requiredAuthorities must not be null");
			Assert.noNullElements(requiredAuthorities, "requiredAuthorities must not contain null");
			Assert.notNull(match, "match must not be null");
			requiredAuthorities = Set.copyOf(requiredAuthorities);
			Assert.isTrue(requiredAuthorities.stream().allMatch(org.springframework.util.StringUtils::hasText),
					"authorities must not be blank");
		}

		public static Rule authenticated() {
			return new Rule(Set.of(), Match.ALL);
		}

		public static Rule requireAll(String... authorities) {
			return new Rule(Set.of(authorities), Match.ALL);
		}

		public static Rule requireAny(String... authorities) {
			return new Rule(Set.of(authorities), Match.ANY);
		}

	}

}
