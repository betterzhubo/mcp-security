CREATE TABLE mcp_api_keys (
    key_id VARCHAR(255) PRIMARY KEY,
    secret_hash VARCHAR(512) NOT NULL,
    expires_at TIMESTAMP NULL,
    enabled BOOLEAN NOT NULL
);

CREATE TABLE mcp_api_key_authorities (
    key_id VARCHAR(255) NOT NULL,
    authority VARCHAR(255) NOT NULL,
    PRIMARY KEY (key_id, authority),
    CONSTRAINT fk_mcp_api_key_authorities_key
        FOREIGN KEY (key_id) REFERENCES mcp_api_keys (key_id)
);
