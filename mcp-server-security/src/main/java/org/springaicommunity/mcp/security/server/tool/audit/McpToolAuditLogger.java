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

/**
 * Receives sanitized audit events for MCP tool invocations.
 *
 * <p>
 * Applications can forward events to an audit platform or durable event store. Implementations
 * must not add tool arguments, tool results, credentials, or exception messages.
 */
@FunctionalInterface
public interface McpToolAuditLogger {

	/**
	 * Record an audit event.
	 * @param event sanitized tool audit event
	 */
	void log(McpToolAuditEvent event);

	/**
	 * Record an event without allowing a failing audit sink to interrupt tool execution.
	 * @param event sanitized tool audit event
	 */
	default void logSafely(McpToolAuditEvent event) {
		try {
			log(event);
		}
		catch (RuntimeException ex) {
			java.util.logging.Logger.getLogger(McpToolAuditLogger.class.getName())
				.log(java.util.logging.Level.SEVERE, "MCP tool audit sink failed (exception type={0})",
						ex.getClass().getName());
		}
	}

}
