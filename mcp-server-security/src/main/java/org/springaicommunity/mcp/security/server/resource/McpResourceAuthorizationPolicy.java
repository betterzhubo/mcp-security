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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriTemplate;

/**
 * Immutable authorization policy for MCP resource reads.
 *
 * <p>
 * Rules are keyed by an exact resource URI or an RFC 6570 URI template. Exact URI rules
 * take precedence over templates. If multiple templates match one URI, access is denied
 * to avoid relying on ambiguous policy ordering. Resources without a matching rule are
 * denied by default.
 */
public final class McpResourceAuthorizationPolicy {

	private final Map<String, Rule> rules;

	private final List<UriRule> uriTemplates;

	public McpResourceAuthorizationPolicy(Map<String, Rule> rules) {
		Assert.notNull(rules, "rules must not be null");
		Assert.noNullElements(rules.keySet(), "resource URI patterns must not contain null");
		Assert.noNullElements(rules.values(), "rules must not contain null");
		Assert.isTrue(rules.keySet().stream().allMatch(StringUtils::hasText),
				"resource URI patterns must not be blank");
		this.rules = Map.copyOf(rules);
		List<UriRule> templates = new ArrayList<>();
		rules.forEach((pattern, rule) -> {
			if (pattern.contains("{")) {
				templates.add(new UriRule(new UriTemplate(pattern), rule));
			}
		});
		this.uriTemplates = List.copyOf(templates);
	}

	/**
	 * Determine whether an authenticated principal may read the requested resource URI.
	 * @param resourceUri requested resource URI
	 * @param authentication current authenticated principal
	 * @return {@code true} only when one unambiguous matching rule is satisfied
	 */
	public boolean isAllowed(String resourceUri, @Nullable Authentication authentication) {
		Assert.hasText(resourceUri, "resourceUri must not be empty");
		if (authentication == null || !authentication.isAuthenticated()
				|| new AuthenticationTrustResolverImpl().isAnonymous(authentication)) {
			return false;
		}

		Rule rule = this.rules.get(resourceUri);
		if (rule == null) {
			for (UriRule uriRule : this.uriTemplates) {
				if (uriRule.uriTemplate().matches(resourceUri)) {
					if (rule != null) {
						return false;
					}
					rule = uriRule.rule();
				}
			}
		}
		return rule != null && rule.isSatisfiedBy(authentication);
	}

	private record UriRule(UriTemplate uriTemplate, Rule rule) {
	}

	/**
	 * Required authorities and their matching semantics for one resource URI.
	 *
	 * @param requiredAuthorities authorities required by the rule
	 * @param match whether all or at least one authority must be present
	 */
	public record Rule(Set<String> requiredAuthorities, Match match) {

		public Rule {
			Assert.notNull(requiredAuthorities, "requiredAuthorities must not be null");
			Assert.noNullElements(requiredAuthorities, "requiredAuthorities must not contain null");
			Assert.notNull(match, "match must not be null");
			requiredAuthorities = Set.copyOf(requiredAuthorities);
			Assert.isTrue(requiredAuthorities.stream().allMatch(StringUtils::hasText),
					"authorities must not be blank");
		}

		private boolean isSatisfiedBy(Authentication authentication) {
			if (this.requiredAuthorities.isEmpty()) {
				return true;
			}
			Set<String> granted = authentication.getAuthorities()
				.stream()
				.map(authority -> authority.getAuthority())
				.collect(java.util.stream.Collectors.toUnmodifiableSet());
			return this.match == Match.ALL ? granted.containsAll(this.requiredAuthorities)
					: this.requiredAuthorities.stream().anyMatch(granted::contains);
		}

		/**
		 * Allow any authenticated principal.
		 * @return authenticated-only rule
		 */
		public static Rule authenticated() {
			return new Rule(Set.of(), Match.ALL);
		}

		/**
		 * Require every listed authority.
		 * @param authorities required authorities
		 * @return all-authorities rule
		 */
		public static Rule requireAll(String... authorities) {
			return new Rule(Set.of(authorities), Match.ALL);
		}

		/**
		 * Require at least one listed authority.
		 * @param authorities accepted authorities
		 * @return any-authority rule
		 */
		public static Rule requireAny(String... authorities) {
			return new Rule(Set.of(authorities), Match.ANY);
		}

	}

	public enum Match {

		ALL, ANY

	}

}
