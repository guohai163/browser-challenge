CREATE TABLE IF NOT EXISTS risk_fingerprint_whitelist (
  id BIGSERIAL PRIMARY KEY,
  browser_family VARCHAR(32) NOT NULL,
  major_version INT NOT NULL,
  ja3 VARCHAR(255) NOT NULL,
  ja4 VARCHAR(255) NOT NULL,
  h2 VARCHAR(255) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  source VARCHAR(64) NOT NULL DEFAULT 'browser_capture',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_risk_fp_lookup
ON risk_fingerprint_whitelist (enabled, browser_family, major_version, ja3, ja4, h2);
