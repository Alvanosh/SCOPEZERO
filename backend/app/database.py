import sqlite3
from contextlib import contextmanager
from .config import DB_PATH
@contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB_PATH,timeout=30)
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    finally: c.close()
def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS engagements(
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, root_domain TEXT NOT NULL,
          scope_json TEXT NOT NULL, exclusions_json TEXT NOT NULL DEFAULT '[]',
          authorized INTEGER NOT NULL, created TEXT NOT NULL, expires TEXT
        );
        CREATE TABLE IF NOT EXISTS scans(
          id INTEGER PRIMARY KEY, engagement_id INTEGER, domain TEXT NOT NULL,
          started TEXT NOT NULL, finished TEXT, status TEXT NOT NULL,
          progress INTEGER NOT NULL DEFAULT 0, stage TEXT DEFAULT 'Queued',
          error TEXT, options TEXT, summary TEXT,
          FOREIGN KEY(engagement_id) REFERENCES engagements(id)
        );
        CREATE TABLE IF NOT EXISTS assets(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, host TEXT NOT NULL,
          kind TEXT NOT NULL, source TEXT, dns TEXT, ownership TEXT,
          confidence INTEGER, evidence TEXT, tls TEXT,
          UNIQUE(scan_id,host,kind), FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS edges(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, source TEXT,
          target TEXT, relation TEXT, evidence TEXT,
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS findings(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, host TEXT,
          category TEXT, title TEXT, severity TEXT, score INTEGER,
          description TEXT, evidence TEXT, recommendation TEXT,
          status TEXT DEFAULT 'Open',
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE INDEX IF NOT EXISTS assets_scan_idx ON assets(scan_id);
        CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings(scan_id);
        CREATE TABLE IF NOT EXISTS vulnerability_intel(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, host TEXT NOT NULL,
          cve TEXT NOT NULL, description TEXT, cvss REAL, severity TEXT,
          epss REAL, kev INTEGER DEFAULT 0, source TEXT, confidence TEXT,
          UNIQUE(scan_id,host,cve), FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS asset_observations(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, host TEXT NOT NULL,
          source TEXT NOT NULL, observed_at TEXT NOT NULL, evidence TEXT,
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE INDEX IF NOT EXISTS vuln_scan_idx ON vulnerability_intel(scan_id);
        CREATE TABLE IF NOT EXISTS ownership_cases(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, host TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'Under investigation', notes TEXT NOT NULL DEFAULT '',
          updated TEXT NOT NULL, UNIQUE(scan_id,host),
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS remediation_records(
          id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL UNIQUE, scan_id INTEGER NOT NULL,
          owner TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'Detected',
          due_date TEXT, notes TEXT NOT NULL DEFAULT '', created TEXT NOT NULL, updated TEXT NOT NULL,
          FOREIGN KEY(finding_id) REFERENCES findings(id), FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS audit_events(
          id INTEGER PRIMARY KEY, scan_id INTEGER, event_type TEXT NOT NULL,
          entity TEXT NOT NULL, details TEXT NOT NULL, created TEXT NOT NULL,
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE INDEX IF NOT EXISTS ownership_scan_idx ON ownership_cases(scan_id);
        CREATE INDEX IF NOT EXISTS remediation_scan_idx ON remediation_records(scan_id);
        CREATE INDEX IF NOT EXISTS audit_scan_idx ON audit_events(scan_id);
        CREATE TABLE IF NOT EXISTS surface_observations(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, host TEXT NOT NULL,
          category TEXT NOT NULL, target TEXT NOT NULL, status INTEGER,
          source TEXT NOT NULL, confidence INTEGER NOT NULL DEFAULT 50,
          evidence TEXT NOT NULL, observed_at TEXT NOT NULL,
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE INDEX IF NOT EXISTS surface_scan_idx ON surface_observations(scan_id);
        CREATE INDEX IF NOT EXISTS surface_host_idx ON surface_observations(scan_id,host);
        CREATE TABLE IF NOT EXISTS tool_jobs(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, engagement_id INTEGER,
          tool TEXT NOT NULL, status TEXT NOT NULL, progress INTEGER NOT NULL DEFAULT 0,
          stage TEXT NOT NULL DEFAULT 'Queued', result_json TEXT, error TEXT,
          created TEXT NOT NULL, started TEXT, finished TEXT,
          FOREIGN KEY(scan_id) REFERENCES scans(id), FOREIGN KEY(engagement_id) REFERENCES engagements(id)
        );
        CREATE INDEX IF NOT EXISTS jobs_scan_idx ON tool_jobs(scan_id,created);
        CREATE TABLE IF NOT EXISTS normalized_observations(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, job_id INTEGER,
          entity TEXT NOT NULL, entity_type TEXT NOT NULL, relation TEXT,
          source_tool TEXT NOT NULL, observed_at TEXT NOT NULL, confidence INTEGER NOT NULL DEFAULT 70,
          data_json TEXT NOT NULL,
          FOREIGN KEY(scan_id) REFERENCES scans(id), FOREIGN KEY(job_id) REFERENCES tool_jobs(id)
        );
        CREATE INDEX IF NOT EXISTS normalized_scan_idx ON normalized_observations(scan_id,entity_type);
        CREATE TABLE IF NOT EXISTS offensive_runs(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, module TEXT NOT NULL,
          status TEXT NOT NULL, results TEXT NOT NULL, created TEXT NOT NULL,
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE INDEX IF NOT EXISTS offensive_scan_idx ON offensive_runs(scan_id,module);
        CREATE TABLE IF NOT EXISTS pentest_evidence(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, finding_id INTEGER,
          title TEXT NOT NULL, evidence_type TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
          request_text TEXT, response_text TEXT, attachment_path TEXT, created TEXT NOT NULL,
          FOREIGN KEY(scan_id) REFERENCES scans(id), FOREIGN KEY(finding_id) REFERENCES findings(id)
        );

        CREATE TABLE IF NOT EXISTS live_events(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, event_type TEXT NOT NULL,
          severity TEXT NOT NULL DEFAULT 'info', title TEXT NOT NULL, message TEXT NOT NULL,
          payload_json TEXT NOT NULL DEFAULT '{}', created TEXT NOT NULL,
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE INDEX IF NOT EXISTS live_events_scan_idx ON live_events(scan_id,id);
        CREATE TABLE IF NOT EXISTS request_lab_runs(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, url TEXT NOT NULL, method TEXT NOT NULL,
          status_code INTEGER, elapsed_ms INTEGER, request_hash TEXT NOT NULL, response_hash TEXT,
          request_text TEXT NOT NULL, response_text TEXT NOT NULL DEFAULT '', created TEXT NOT NULL,
          FOREIGN KEY(scan_id) REFERENCES scans(id));
        CREATE INDEX IF NOT EXISTS request_lab_scan_idx ON request_lab_runs(scan_id,created);
        CREATE TABLE IF NOT EXISTS api_access_matrix(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, endpoint TEXT NOT NULL, method TEXT NOT NULL,
          identity TEXT NOT NULL, outcome TEXT NOT NULL, status_code INTEGER, evidence TEXT NOT NULL DEFAULT '',
          created TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(id));
        CREATE INDEX IF NOT EXISTS api_matrix_scan_idx ON api_access_matrix(scan_id,endpoint);
        CREATE TABLE IF NOT EXISTS investigation_notes(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
          asset TEXT, created TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(id));

        CREATE TABLE IF NOT EXISTS web_security_checks(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, url TEXT NOT NULL,
          check_type TEXT NOT NULL, verdict TEXT NOT NULL, confidence INTEGER NOT NULL,
          evidence TEXT NOT NULL, created TEXT NOT NULL,
          FOREIGN KEY(scan_id) REFERENCES scans(id));
        CREATE INDEX IF NOT EXISTS web_checks_scan_idx ON web_security_checks(scan_id,created);

        CREATE TABLE IF NOT EXISTS web_test_identities(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, label TEXT NOT NULL,
          host TEXT NOT NULL, encrypted_headers TEXT NOT NULL, key_version INTEGER NOT NULL DEFAULT 1,
          created TEXT NOT NULL, updated TEXT NOT NULL, last_verified TEXT,
          UNIQUE(scan_id,label), FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS web_session_comparisons(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, identity_a INTEGER NOT NULL,
          identity_b INTEGER NOT NULL, url TEXT NOT NULL, method TEXT NOT NULL,
          status_a INTEGER, status_b INTEGER, hash_a TEXT, hash_b TEXT,
          verdict TEXT NOT NULL, evidence TEXT NOT NULL, finding_id INTEGER,
          created TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(id),
          FOREIGN KEY(identity_a) REFERENCES web_test_identities(id),
          FOREIGN KEY(identity_b) REFERENCES web_test_identities(id),
          FOREIGN KEY(finding_id) REFERENCES findings(id)
        );
        CREATE TABLE IF NOT EXISTS differential_runs(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, url TEXT NOT NULL,
          test_type TEXT NOT NULL, verdict TEXT NOT NULL, confidence INTEGER NOT NULL,
          baseline_status INTEGER, comparison_status INTEGER, baseline_hash TEXT,
          comparison_hash TEXT, evidence TEXT NOT NULL, created TEXT NOT NULL,
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE INDEX IF NOT EXISTS differential_scan_idx ON differential_runs(scan_id,created);

        CREATE TABLE IF NOT EXISTS pipeline_runs(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL UNIQUE,
          engagement_id INTEGER NOT NULL, status TEXT NOT NULL,
          stage TEXT NOT NULL, progress INTEGER NOT NULL DEFAULT 0,
          stages_json TEXT NOT NULL DEFAULT '{}', error TEXT,
          created TEXT NOT NULL, started TEXT, finished TEXT,
          FOREIGN KEY(scan_id) REFERENCES scans(id),
          FOREIGN KEY(engagement_id) REFERENCES engagements(id)
        );
        CREATE INDEX IF NOT EXISTS pipeline_status_idx ON pipeline_runs(status,created);

        CREATE TABLE IF NOT EXISTS alerts(
          id INTEGER PRIMARY KEY, engagement_id INTEGER, scan_id INTEGER, finding_id INTEGER,
          category TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info',
          title TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New',
          assigned_to TEXT, analyst_note TEXT NOT NULL DEFAULT '',
          fingerprint TEXT NOT NULL UNIQUE, created TEXT NOT NULL, updated TEXT NOT NULL,
          FOREIGN KEY(engagement_id) REFERENCES engagements(id),
          FOREIGN KEY(scan_id) REFERENCES scans(id),
          FOREIGN KEY(finding_id) REFERENCES findings(id)
        );
        CREATE INDEX IF NOT EXISTS alerts_engagement_idx ON alerts(engagement_id,status,severity,created);

        CREATE TABLE IF NOT EXISTS validation_records(
          id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, finding_id INTEGER,
          verdict TEXT NOT NULL, rationale TEXT NOT NULL, validated_by TEXT NOT NULL DEFAULT '',
          created TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scans(id),
          FOREIGN KEY(finding_id) REFERENCES findings(id)
        );
        """)
        cols={r[1] for r in c.execute("PRAGMA table_info(pentest_evidence)").fetchall()}
        if "sha256" not in cols: c.execute("ALTER TABLE pentest_evidence ADD COLUMN sha256 TEXT")
        cols={r[1] for r in c.execute("PRAGMA table_info(findings)").fetchall()}
        if "confidence" not in cols: c.execute("ALTER TABLE findings ADD COLUMN confidence INTEGER NOT NULL DEFAULT 50")
