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

package org.springaicommunity.mcp.security.server.tool.audit;

import java.time.Instant;

import org.jspecify.annotations.Nullable;

/**
 * Sanitized audit event for an MCP tool invocation.
 *
 * <p>
 * Events deliberately exclude tool arguments, tool results, credentials, and exception
 * messages. Caller identifies the authenticated principal when available.
 *
 * @param occurredAt event timestamp
 * @param toolName invoked MCP tool name
 * @param caller authenticated principal name, or {@code null} when unavailable
 * @param outcome invocation outcome
 * @param reason stable, non-sensitive reason code
 * @param durationMillis elapsed invocation time in milliseconds
 */
public record McpToolAuditEvent(Instant occurredAt, String toolName, @Nullable String caller, Outcome outcome,
		Reason reason, long durationMillis) {

	public enum Outcome {

		DENIED, SUCCESS, FAILURE

	}

	public enum Reason {

		AUTHORIZATION_DENIED, NONE, TOOL_ERROR_RESULT, HANDLER_EXCEPTION

	}

}
