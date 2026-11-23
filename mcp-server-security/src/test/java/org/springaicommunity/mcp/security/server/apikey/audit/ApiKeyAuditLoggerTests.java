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

package org.springaicommunity.mcp.security.server.apikey.audit;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link ApiKeyAuditLogger}.
 */
class ApiKeyAuditLoggerTests {

	@Test
	void auditSinkFailureDoesNotEscapeTheSafeLoggingBoundary() {
		ApiKeyAuditLogger logger = event -> {
			throw new IllegalStateException("sensitive-value-must-not-be-logged");
		};
		var event = new ApiKeyAuditEvent(Instant.parse("2026-11-23T00:00:00Z"),
				ApiKeyAuditEvent.Action.AUTHENTICATE, "key-1", List.of(), ApiKeyAuditEvent.Outcome.SUCCESS,
				ApiKeyAuditEvent.Reason.NONE);

		assertThatCode(() -> logger.logSafely(event)).doesNotThrowAnyException();
	}

	@Test
	void auditEventCopiesGrantedAuthorities() {
		var authorities = new java.util.ArrayList<>(List.of("SCOPE_weather.read"));
		var event = new ApiKeyAuditEvent(Instant.parse("2026-11-23T00:00:00Z"),
				ApiKeyAuditEvent.Action.CREATE, "key-1", authorities, ApiKeyAuditEvent.Outcome.SUCCESS,
				ApiKeyAuditEvent.Reason.NONE);

		assertThatThrownBy(() -> authorities.add("SCOPE_weather.write")).doesNotThrowAnyException();
		assertThat(event.authorities()).containsExactly("SCOPE_weather.read");
	}

}
