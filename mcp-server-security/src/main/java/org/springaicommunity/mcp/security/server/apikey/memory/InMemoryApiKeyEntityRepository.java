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

package org.springaicommunity.mcp.security.server.apikey.memory;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityManagementRepository;

/**
 * In-memory {@link ApiKeyEntityManagementRepository} backed by concurrent collections.
 *
 * @author Daniel Garnier-Moiroux
 */
public class InMemoryApiKeyEntityRepository<T extends ApiKeyEntity> implements ApiKeyEntityManagementRepository<T> {

	private final Map<String, T> apiKeys = new ConcurrentHashMap<>();

	private final Set<String> disabledApiKeys = ConcurrentHashMap.newKeySet();

	public InMemoryApiKeyEntityRepository() {
	}

	public InMemoryApiKeyEntityRepository(Collection<T> apiKeyEntities) {
		apiKeyEntities.forEach(entity -> this.apiKeys.put(entity.getId(), entity));
	}

	@Override
	public @Nullable T findByKeyId(String keyId) {
		var key = this.apiKeys.get(keyId);
		return key != null ? key.copy() : null;
	}

	public synchronized void addApiKey(T value) {
		this.apiKeys.put(value.getId(), value);
		this.disabledApiKeys.remove(value.getId());
	}

	public synchronized void removeApiKey(String keyId) {
		revokeApiKey(keyId);
	}

	public boolean containsApiKey(String keyId) {
		return this.apiKeys.containsKey(keyId);
	}

	/**
	 * Add a replacement key without interrupting requests authenticated with the current
	 * key. The current key remains enabled until it is explicitly revoked or disabled.
	 * @param currentKeyId the ID of the key being rotated
	 * @param replacement the replacement key
	 * @return {@code true} when the replacement key was added
	 */
	@Override
	public synchronized boolean rotateApiKey(String currentKeyId, T replacement) {
		if (currentKeyId == null || currentKeyId.isBlank() || replacement == null
				|| currentKeyId.equals(replacement.getId()) || !isEnabled(currentKeyId)) {
			return false;
		}
		if (this.apiKeys.putIfAbsent(replacement.getId(), replacement) != null) {
			return false;
		}
		this.disabledApiKeys.remove(replacement.getId());
		return true;
	}

	@Override
	public boolean isEnabled(String keyId) {
		return this.apiKeys.containsKey(keyId) && !this.disabledApiKeys.contains(keyId);
	}

	@Override
	public synchronized boolean enableApiKey(String keyId) {
		if (!this.apiKeys.containsKey(keyId)) {
			return false;
		}
		this.disabledApiKeys.remove(keyId);
		return true;
	}

	@Override
	public synchronized boolean disableApiKey(String keyId) {
		if (!this.apiKeys.containsKey(keyId)) {
			return false;
		}
		this.disabledApiKeys.add(keyId);
		return true;
	}

	@Override
	public synchronized boolean revokeApiKey(String keyId) {
		var removed = this.apiKeys.remove(keyId);
		this.disabledApiKeys.remove(keyId);
		return removed != null;
	}

}
