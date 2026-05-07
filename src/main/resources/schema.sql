CREATE TABLE IF NOT EXISTS risk_fingerprint_whitelist (
  id BIGSERIAL PRIMARY KEY,
  browser_family VARCHAR(32) NOT NULL,
  major_version INT NOT NULL,
  ja3 VARCHAR(255) NOT NULL,
  ja3_raw_normalized TEXT NOT NULL DEFAULT '',
  ja3_md5_normalized VARCHAR(255) NOT NULL DEFAULT '',
  ja4 VARCHAR(255) NOT NULL,
  h2 VARCHAR(255) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  source VARCHAR(64) NOT NULL DEFAULT 'browser_capture',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE risk_fingerprint_whitelist
  ADD COLUMN IF NOT EXISTS ja3_raw_normalized TEXT NOT NULL DEFAULT '';

ALTER TABLE risk_fingerprint_whitelist
  ADD COLUMN IF NOT EXISTS ja3_md5_normalized VARCHAR(255) NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_risk_fp_lookup
ON risk_fingerprint_whitelist (enabled, browser_family, major_version, ja3_md5_normalized, ja4, h2);
