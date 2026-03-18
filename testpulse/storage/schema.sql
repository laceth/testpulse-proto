CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  testcase_id TEXT,
  observed_decision TEXT,
  expected_decision TEXT,
  functional_pass INTEGER,
  classification TEXT,
  confidence REAL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  bundle_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics (
  run_id TEXT NOT NULL,
  metric_key TEXT NOT NULL,
  metric_value REAL,
  PRIMARY KEY (run_id, metric_key),
  FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS component_health (
  run_id TEXT NOT NULL,
  component TEXT NOT NULL,
  status TEXT,
  severity TEXT,
  confidence REAL,
  finding TEXT,
  recommendation TEXT,
  PRIMARY KEY (run_id, component),
  FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);
