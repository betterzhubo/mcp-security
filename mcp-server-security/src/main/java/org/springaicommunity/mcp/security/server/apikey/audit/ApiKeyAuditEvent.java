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

import org.jspecify.annotations.Nullable;

/**
 * Sanitized audit event for API key authentication and lifecycle operations.
 *
 * <p>
 * Events intentionally contain no API key secret, encoded secret, request body, or
 * exception message. The key identifier is included to support incident investigation.
 * </p>
 *
 * @param occurredAt event timestamp
 * @param action operation that produced the event
 * @param keyId public API key identifier, or {@code null} when unavailable
 * @param outcome operation outcome
 * @param reason stable, non-sensitive reason code
 */
public record ApiKeyAuditEvent(Instant occurredAt, Action action, @Nullable String keyId, List<String> authorities,
		Outcome outcome, Reason reason) {

	public ApiKeyAuditEvent {
		authorities = List.copyOf(authorities);
	}

	public enum Action {

		AUTHENTICATE, CREATE, READ, ENABLE, DISABLE, REVOKE, ROTATE

	}

	public enum Outcome {

		SUCCESS, FAILURE

	}

	public enum Reason {

		NONE, MISSING_CREDENTIALS, KEY_NOT_FOUND, KEY_DISABLED, SECRET_MISMATCH, KEY_EXPIRED, ACCESS_DENIED,
		INVALID_REQUEST, OPERATION_REJECTED, INTERNAL_ERROR

	}

}
