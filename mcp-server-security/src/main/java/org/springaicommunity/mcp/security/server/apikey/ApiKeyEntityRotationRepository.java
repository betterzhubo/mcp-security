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

package org.springaicommunity.mcp.security.server.apikey;

/**
 * Optional API key rotation operations for repositories that support a safe transition
 * between old and replacement credentials.
 *
 * @author Daniel Garnier-Moiroux
 */
public interface ApiKeyEntityRotationRepository<T extends ApiKeyEntity> extends ApiKeyEntityLifecycleRepository<T> {

	/**
	 * Add a replacement API key while keeping the current key enabled. The replacement
	 * must have a different ID that is not already present in the repository.
	 * @param currentKeyId the ID of the currently active API key
	 * @param replacement the replacement API key to add
	 * @return {@code true} when the replacement was added
	 */
	boolean rotateApiKey(String currentKeyId, T replacement);

}
