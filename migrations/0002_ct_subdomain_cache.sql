
CREATE TABLE ct_subdomain_cache (
    domain VARCHAR(255) PRIMARY KEY,
    source VARCHAR(64) NOT NULL,
    subdomains_json LONGTEXT NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL
);

CREATE INDEX idx_ct_subdomain_cache_updated_at ON ct_subdomain_cache(updated_at);