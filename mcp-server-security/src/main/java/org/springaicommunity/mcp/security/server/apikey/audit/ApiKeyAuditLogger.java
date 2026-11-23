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

/**
 * Receives sanitized API key audit events.
 *
 * <p>
 * Applications may provide an implementation that forwards events to their audit platform
 * or durable event store. Implementations should not include credential material in their
 * output.
 * </p>
 */
@FunctionalInterface
public interface ApiKeyAuditLogger {

	/**
	 * Record an audit event.
	 * @param event sanitized audit event
	 */
	void log(ApiKeyAuditEvent event);

	/**
	 * Record an event without allowing a failing audit sink to interrupt authentication
	 * or key management. A sink failure is reported through the JDK logger.
	 * @param event sanitized audit event
	 */
	default void logSafely(ApiKeyAuditEvent event) {
		try {
			log(event);
		}
		catch (RuntimeException ex) {
			java.util.logging.Logger.getLogger(ApiKeyAuditLogger.class.getName())
				.log(java.util.logging.Level.SEVERE, "API key audit sink failed", ex);
		}
	}

}
