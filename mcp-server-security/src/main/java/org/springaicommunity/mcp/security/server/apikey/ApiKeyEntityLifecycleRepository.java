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
 * Optional lifecycle operations for repositories that manage API key activation and
 * revocation.
 */
public interface ApiKeyEntityLifecycleRepository<T extends ApiKeyEntity> extends ApiKeyEntityRepository<T> {

	/**
	 * Determine whether an API key currently exists and is enabled.
	 * @param keyId the API key identifier
	 * @return {@code true} when the key exists and is enabled
	 */
	boolean isEnabled(String keyId);

	/**
	 * Enable an existing API key.
	 * @param keyId the API key identifier
	 * @return {@code true} when the key exists and was enabled
	 */
	boolean enableApiKey(String keyId);

	/**
	 * Disable an existing API key without removing its stored credentials.
	 * @param keyId the API key identifier
	 * @return {@code true} when the key exists and was disabled
	 */
	boolean disableApiKey(String keyId);

	/**
	 * Revoke an API key by permanently removing it from this repository.
	 * @param keyId the API key identifier
	 * @return {@code true} when a key was removed
	 */
	boolean revokeApiKey(String keyId);

}
