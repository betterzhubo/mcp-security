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

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * JDK logging implementation of {@link ApiKeyAuditLogger}.
 */
public class DefaultApiKeyAuditLogger implements ApiKeyAuditLogger {

	private static final Logger LOGGER = Logger.getLogger(DefaultApiKeyAuditLogger.class.getName());

	@Override
	public void log(ApiKeyAuditEvent event) {
		Level level = event.outcome() == ApiKeyAuditEvent.Outcome.SUCCESS ? Level.INFO : Level.WARNING;
		LOGGER.log(level, "API key audit action={0} keyId={1} outcome={2} reason={3} occurredAt={4}",
				new Object[] { event.action(), event.keyId(), event.outcome(), event.reason(), event.occurredAt() });
	}

}
