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

package org.springaicommunity.mcp.security.server.apikey.jdbc;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityRotationRepository;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/**
 * JDBC-backed API key repository supporting lifecycle management and overlapping key
 * rotation. Secrets must be supplied as encoded values, as produced by the API key
 * entity's configured {@code PasswordEncoder}.
 *
 */
public class JdbcApiKeyEntityRepository implements ApiKeyEntityRotationRepository<ApiKeyEntity> {

	private static final RowMapper<KeyRow> KEY_ROW_MAPPER = (rs, rowNum) -> {
		@Nullable Timestamp expiresAt = rs.getTimestamp("expires_at");
		return new KeyRow(rs.getString("key_id"), rs.getString("secret_hash"),
				expiresAt != null ? expiresAt.toInstant() : null);
	};

	private final JdbcTemplate jdbcTemplate;

	private final TransactionTemplate transactionTemplate;

	public JdbcApiKeyEntityRepository(JdbcTemplate jdbcTemplate, PlatformTransactionManager transactionManager) {
		Assert.notNull(jdbcTemplate, "jdbcTemplate must not be null");
		Assert.notNull(transactionManager, "transactionManager must not be null");
		this.jdbcTemplate = jdbcTemplate;
		this.transactionTemplate = new TransactionTemplate(transactionManager);
	}

	@Override
	public @Nullable ApiKeyEntity findByKeyId(String keyId) {
		List<KeyRow> rows = this.jdbcTemplate
			.query("SELECT key_id, secret_hash, expires_at FROM mcp_api_keys WHERE key_id = ?", KEY_ROW_MAPPER, keyId);
		if (rows.isEmpty()) {
			return null;
		}
		KeyRow row = rows.get(0);
		List<GrantedAuthority> authorities = this.jdbcTemplate.query(
				"SELECT authority FROM mcp_api_key_authorities WHERE key_id = ? ORDER BY authority",
				(rs, rowNum) -> new SimpleGrantedAuthority(rs.getString("authority")), keyId);
		return new JdbcApiKeyEntity(row.keyId(), row.secretHash(), authorities, row.expiresAt());
	}

	/**
	 * Insert an API key and its authorities in one transaction. The supplied entity's
	 * secret must already be encoded; plaintext secrets are never persisted by this
	 * repository.
	 * @param entity API key entity to store
	 */
	public void addApiKey(ApiKeyEntity entity) {
		Assert.notNull(entity, "entity must not be null");
		this.transactionTemplate.executeWithoutResult(status -> insertEntity(entity));
	}

	@Override
	public boolean isEnabled(String keyId) {
		List<Boolean> values = this.jdbcTemplate.query("SELECT enabled FROM mcp_api_keys WHERE key_id = ?",
				(rs, rowNum) -> rs.getBoolean("enabled"), keyId);
		return !values.isEmpty() && values.get(0);
	}

	@Override
	public boolean enableApiKey(String keyId) {
		return this.jdbcTemplate.update("UPDATE mcp_api_keys SET enabled = TRUE WHERE key_id = ?", keyId) == 1;
	}

	@Override
	public boolean disableApiKey(String keyId) {
		return this.jdbcTemplate.update("UPDATE mcp_api_keys SET enabled = FALSE WHERE key_id = ?", keyId) == 1;
	}

	@Override
	public boolean revokeApiKey(String keyId) {
		Boolean revoked = this.transactionTemplate.execute(status -> {
			this.jdbcTemplate.update("DELETE FROM mcp_api_key_authorities WHERE key_id = ?", keyId);
			return this.jdbcTemplate.update("DELETE FROM mcp_api_keys WHERE key_id = ?", keyId) == 1;
		});
		return Boolean.TRUE.equals(revoked);
	}

	@Override
	public boolean rotateApiKey(String currentKeyId, ApiKeyEntity replacement) {
		Assert.notNull(replacement, "replacement must not be null");
		try {
			Boolean rotated = this.transactionTemplate.execute(status -> {
				if (currentKeyId == null || currentKeyId.isBlank() || currentKeyId.equals(replacement.getId())
						|| !isEnabledForUpdate(currentKeyId)) {
					return false;
				}
				try {
					insertKey(replacement);
				}
				catch (DuplicateKeyException ex) {
					return false;
				}
				insertAuthorities(replacement);
				return true;
			});
			return Boolean.TRUE.equals(rotated);
		}
		catch (DuplicateKeyException ex) {
			return false;
		}
	}

	private boolean isEnabledForUpdate(String keyId) {
		List<Boolean> values = this.jdbcTemplate.query("SELECT enabled FROM mcp_api_keys WHERE key_id = ? FOR UPDATE",
				(rs, rowNum) -> rs.getBoolean("enabled"), keyId);
		return !values.isEmpty() && values.get(0);
	}

	private void insertEntity(ApiKeyEntity entity) {
		insertKey(entity);
		insertAuthorities(entity);
	}

	private void insertKey(ApiKeyEntity entity) {
		@Nullable String secretHash = entity.getSecret();
		Assert.hasText(secretHash, "entity secret must not be null or blank");
		@Nullable Instant expiresAt = entity.getExpiresAt();
		this.jdbcTemplate.update(
				"INSERT INTO mcp_api_keys (key_id, secret_hash, expires_at, enabled) VALUES (?, ?, ?, TRUE)",
				entity.getId(), secretHash, expiresAt != null ? Timestamp.from(expiresAt) : null);
	}

	private void insertAuthorities(ApiKeyEntity entity) {
		for (var authority : entity.getAuthorities()) {
			this.jdbcTemplate.update("INSERT INTO mcp_api_key_authorities (key_id, authority) VALUES (?, ?)",
					entity.getId(), authority.getAuthority());
		}
	}

	private record KeyRow(String keyId, String secretHash, @Nullable Instant expiresAt) {
	}

	private static final class JdbcApiKeyEntity implements ApiKeyEntity {

		private final String id;

		private @Nullable String secret;

		private final List<GrantedAuthority> authorities;

		private final @Nullable Instant expiresAt;

		private JdbcApiKeyEntity(String id, @Nullable String secret, List<GrantedAuthority> authorities,
				@Nullable Instant expiresAt) {
			this.id = id;
			this.secret = secret;
			this.authorities = List.copyOf(authorities);
			this.expiresAt = expiresAt;
		}

		@Override
		public String getId() {
			return this.id;
		}

		@Override
		public @Nullable String getSecret() {
			return this.secret;
		}

		@Override
		public List<GrantedAuthority> getAuthorities() {
			return this.authorities;
		}

		@Override
		public @Nullable Instant getExpiresAt() {
			return this.expiresAt;
		}

		@Override
		public void eraseCredentials() {
			this.secret = null;
		}

		@Override
		public JdbcApiKeyEntity copy() {
			return new JdbcApiKeyEntity(this.id, this.secret, this.authorities, this.expiresAt);
		}

	}

}
