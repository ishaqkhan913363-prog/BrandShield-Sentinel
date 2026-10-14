import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import app as sentinel


class AppWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        sentinel.DB_PATH = Path(self.temp_dir.name) / "test-sentinel.db"
        sentinel.app.config.update(TESTING=True, SECRET_KEY="test-secret",
                                   WTF_CSRF_ENABLED=False)
        sentinel.init_db()
        self.client = sentinel.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def sign_in(self):
        return self.client.post("/login", data={
            "email": "demo@sentinel.local",
            "password": "SentinelDemo!26",
        }, follow_redirects=True)

    def test_demo_login_and_dashboard_show_workspace_totals(self):
        response = self.sign_in()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Risk distribution across all saved records", response.data)
        self.assertIn(b"All records", response.data)

    def test_new_empty_workspace_has_zero_counts(self):
        response = self.client.post("/signup", data={
            "email": "analyst@example.test",
            "password": "long-test-password",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b">None</div>", response.data)
        self.assertIn(b"No candidates yet", response.data)

    def test_profile_shows_and_saves_name_and_sidebar_identity(self):
        self.sign_in()
        profile_response = self.client.get("/profile")
        self.assertEqual(profile_response.status_code, 200)
        self.assertIn(b"demo@sentinel.local", profile_response.data)
        self.assertIn(b"Sign out", profile_response.data)

        update_response = self.client.post("/profile", data={
            "full_name": "Avery Analyst",
        }, follow_redirects=True)
        self.assertEqual(update_response.status_code, 200)
        self.assertIn(b"Avery Analyst", update_response.data)
        with sentinel.db() as connection:
            full_name = connection.execute(
                "SELECT full_name FROM users WHERE email='demo@sentinel.local'"
            ).fetchone()["full_name"]
        self.assertEqual(full_name, "Avery Analyst")

        dashboard = self.client.get("/dashboard")
        self.assertIn(b"Avery Analyst", dashboard.data)

    def test_profile_requires_nonempty_name_and_authentication(self):
        self.sign_in()
        response = self.client.post("/profile", data={"full_name": "   "})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your name is required.", response.data)

        self.client.post("/logout")
        response = self.client.get("/profile")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_monitoring_paginates_and_preserves_filters(self):
        self.sign_in()
        with sentinel.db() as connection:
            brand_id = connection.execute(
                "SELECT id FROM brands WHERE name='Northstar'"
            ).fetchone()["id"]
            for index in range(26):
                stamp = sentinel.now()
                connection.execute(
                    """INSERT INTO candidates
                       (brand_id,channel,name,status,source,confidence,risk,rationale,
                        first_seen,last_seen,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (brand_id, "Social", f"Pagination candidate {index}", "New",
                     "Test", 20, "Low", "Test fixture", stamp, stamp, stamp),
                )

        first_page = self.client.get("/monitoring?channel=Social&q=Pagination")
        second_page = self.client.get("/monitoring?channel=Social&q=Pagination&page=2")
        self.assertEqual(first_page.status_code, 200)
        self.assertIn(b"Showing 1\xe2\x80\x9325 of 26 candidate(s)", first_page.data)
        self.assertIn(b"channel=Social", first_page.data)
        self.assertEqual(second_page.status_code, 200)
        self.assertIn(b"Showing 26\xe2\x80\x9326 of 26 candidate(s)", second_page.data)

    def test_csv_import_reports_duplicates_official_and_invalid_rows(self):
        self.sign_in()
        content = (
            "channel,name,url\n"
            "Social,Sample Support,https://social.example/sample\n"
            "Social,Sample Support,https://social.example/sample\n"
            "Social,Official Website,https://northstar.example\n"
            "Social,,https://social.example/blank\n"
            "Other,Unsupported Channel,https://social.example/invalid\n"
        )
        response = self.client.post("/import", data={
            "file": (io.BytesIO(content.encode()), "candidates.csv"),
        }, content_type="multipart/form-data", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"1 added, 1 duplicates, 1 official matches, 2 invalid rows skipped", response.data)
        with sentinel.db() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM candidates WHERE source='CSV import'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_health_endpoint_reports_local_mode(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")
        self.assertEqual(response.json["external_connectors"], "not configured")

    def test_csrf_rejects_state_change_without_token_outside_test_mode(self):
        sentinel.app.config["WTF_CSRF_ENABLED"] = True
        try:
            response = self.client.post("/login", data={
                "email": "demo@sentinel.local",
                "password": "SentinelDemo!26",
            })
            self.assertEqual(response.status_code, 400)
        finally:
            sentinel.app.config["WTF_CSRF_ENABLED"] = False

    def test_production_configuration_requires_secret_and_skips_demo_seed(self):
        env = os.environ.copy()
        env.pop("SENTINEL_SECRET_KEY", None)
        env["SENTINEL_ENV"] = "production"
        env["SENTINEL_DB_PATH"] = str(Path(self.temp_dir.name) / "production.db")
        missing_secret = subprocess.run(
            [sys.executable, "-c", "import app"],
            cwd=sentinel.BASE, env=env, capture_output=True, text=True,
        )
        self.assertNotEqual(missing_secret.returncode, 0)
        self.assertIn("SENTINEL_SECRET_KEY must be configured",
                      missing_secret.stderr)

        env["SENTINEL_SECRET_KEY"] = "test-only-production-secret-key"
        check_config = subprocess.run(
            [sys.executable, "-c", (
                "import json, app\n"
                "with app.db() as connection:\n"
                " print(json.dumps({"
                "'secure_cookie': app.app.config['SESSION_COOKIE_SECURE'], "
                "'csrf': app.app.config['WTF_CSRF_ENABLED'], "
                "'users': connection.execute('SELECT COUNT(*) FROM users').fetchone()[0]"
                "}))\n"
            )],
            cwd=sentinel.BASE, env=env, capture_output=True, text=True,
        )
        self.assertEqual(check_config.returncode, 0, check_config.stderr)
        config = json.loads(check_config.stdout.strip().splitlines()[-1])
        self.assertTrue(config["secure_cookie"])
        self.assertTrue(config["csrf"])
        self.assertEqual(config["users"], 0)

    def add_network_fixture(self):
        self.sign_in()
        with sentinel.db() as connection:
            brand_id = connection.execute(
                "SELECT id FROM brands WHERE name='Northstar'"
            ).fetchone()["id"]
            stamp = sentinel.now()
            records = [
                ("Social", "Support profile", "https://social.test/account/1", "",
                 "Contact +1 (212) 555-0188. Payment page: https://payments.test/invoice/42",
                 "Manual entry", "2026-10-13T22:00:00-04:00"),
                ("App Store", "Rewards companion", "https://payments.test/invoice/42",
                 "Ledger Works", "Companion rewards listing", "CSV import", ""),
            ]
            for channel, name, url, developer, description, source, observed_at in records:
                connection.execute(
                    """INSERT INTO candidates
                       (brand_id,channel,name,url,developer,description,status,source,
                        confidence,risk,rationale,first_seen,last_seen,created_at,observed_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (brand_id, channel, name, url, developer, description, "New", source,
                     65, "High", "Test evidence", stamp, stamp, stamp, observed_at),
                )

    def test_network_correlates_exact_cross_channel_payment_url_with_provenance(self):
        self.add_network_fixture()
        response = self.client.get("/api/network")
        self.assertEqual(response.status_code, 200)
        graph = response.get_json()
        self.assertEqual(len(graph["links"]), 1)
        evidence_types = {item["type"] for item in graph["links"][0]["evidence"]}
        self.assertIn("payment_url", evidence_types)
        self.assertIn("domain", evidence_types)
        self.assertTrue(all(len(item["observed_at"]) == 2 and
                            len(item["time_basis"]) == 2
                            for item in graph["links"][0]["evidence"]))
        payment_evidence = next(item for item in graph["links"][0]["evidence"]
                                if item["type"] == "payment_url")
        self.assertEqual(payment_evidence["observed_at"][0], "2026-10-14T02:00:00Z")
        self.assertEqual(set(payment_evidence["time_basis"]), {"source-reported", "captured"})
        self.assertEqual(len(graph["nodes"]), 6)
        self.assertTrue(any(observation["kind"] == "phone"
                            for node in graph["nodes"]
                            for observation in node["observations"]))

    def test_network_export_contains_explainable_matches(self):
        self.add_network_fixture()
        response = self.client.get("/network/export.csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"shared_identifier", response.data)
        self.assertIn(b"payments.test/invoice/42", response.data)
        self.assertIn(b"not proof of coordination", response.data)

    def test_downloadable_demo_csv_creates_a_cross_platform_network_link(self):
        self.sign_in()
        sample = (sentinel.BASE / "static" / "sample_candidates.csv").read_bytes()
        imported = self.client.post("/import", data={
            "file": (io.BytesIO(sample), "sample_candidates.csv"),
        }, content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(imported.status_code, 200)

        response = self.client.get("/api/network")
        self.assertEqual(response.status_code, 200)
        graph = response.get_json()
        self.assertEqual(len(graph["links"]), 1, graph["links"])
        self.assertEqual(graph["links"][0]["label"], "shared payment URL")
        with sentinel.db() as connection:
            description = connection.execute(
                "SELECT description FROM candidates WHERE name='Northstar Verification Desk'"
            ).fetchone()["description"]
        self.assertIn("DEMO ONLY", description)

    def test_network_api_requires_authentication(self):
        response = self.client.get("/api/network")
        self.assertEqual(response.status_code, 401)

    def test_observation_time_requires_timezone_and_normalizes_to_utc(self):
        self.assertEqual(
            sentinel.parse_observed_at("2026-10-13T22:00:00-04:00"),
            "2026-10-14T02:00:00Z",
        )
        self.assertIsNone(sentinel.parse_observed_at("2026-10-14T08:00:00"))
        self.assertIsNone(sentinel.parse_observed_at("not-a-date"))

    def test_csv_import_accepts_timezone_timestamp_and_skips_naive_time(self):
        self.sign_in()
        content = (
            "channel,name,observed_at\n"
            "Social,Timestamped record,2026-10-13T22:00:00-04:00\n"
            "Social,Naive timestamp record,2026-10-14T08:00:00\n"
        )
        response = self.client.post("/import", data={
            "file": (io.BytesIO(content.encode()), "observations.csv"),
        }, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn(b"1 added, 0 duplicates, 0 official matches, 1 invalid rows skipped",
                      response.data)
        with sentinel.db() as connection:
            observed_at = connection.execute(
                "SELECT observed_at FROM candidates WHERE name='Timestamped record'"
            ).fetchone()["observed_at"]
        self.assertEqual(observed_at, "2026-10-14T02:00:00Z")

    def test_manual_candidate_records_timezone_aware_observation_time(self):
        self.sign_in()
        response = self.client.post("/candidates/add", data={
            "channel": "Social",
            "name": "Timestamped manual case",
            "url": "https://manual-observation.test/profile",
            "observed_at": "2026-10-13T22:00:00-04:00",
        })
        self.assertEqual(response.status_code, 302)
        with sentinel.db() as connection:
            observed_at = connection.execute(
                "SELECT observed_at FROM candidates WHERE name='Timestamped manual case'"
            ).fetchone()["observed_at"]
        self.assertEqual(observed_at, "2026-10-14T02:00:00Z")

    def test_false_positive_cases_are_visible_but_not_linked(self):
        self.add_network_fixture()
        with sentinel.db() as connection:
            connection.execute(
                "UPDATE candidates SET status='False positive' WHERE name='Support profile'"
            )
        response = self.client.get("/api/network")
        self.assertEqual(response.status_code, 200)
        graph = response.get_json()
        self.assertEqual(len(graph["nodes"]), 6)
        self.assertEqual(graph["links"], [])

    def test_common_social_platform_domain_does_not_create_a_link(self):
        self.sign_in()
        with sentinel.db() as connection:
            brand_id = connection.execute(
                "SELECT id FROM brands WHERE name='Northstar'"
            ).fetchone()["id"]
            stamp = sentinel.now()
            for name, path in (("Social record one", "one"), ("Social record two", "two")):
                connection.execute(
                    """INSERT INTO candidates
                       (brand_id,channel,name,url,status,source,confidence,risk,rationale,
                        first_seen,last_seen,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (brand_id, "Social", name, f"https://instagram.com/{path}", "New",
                     "Manual entry", 50, "Medium", "Test", stamp, stamp, stamp),
                )
        response = self.client.get("/api/network")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["links"], [])

    def test_broad_shared_domain_is_reported_but_not_expanded_to_all_pairs(self):
        self.sign_in()
        with sentinel.db() as connection:
            brand_id = connection.execute(
                "SELECT id FROM brands WHERE name='Northstar'"
            ).fetchone()["id"]
            stamp = sentinel.now()
            for index in range(26):
                connection.execute(
                    """INSERT INTO candidates
                       (brand_id,channel,name,url,status,source,confidence,risk,rationale,
                        first_seen,last_seen,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (brand_id, "Social", f"Domain case {index}",
                     f"https://shared-assets.test/case/{index}", "New", "Manual entry",
                     40, "Medium", "Test", stamp, stamp, stamp),
                )
        response = self.client.get("/api/network")
        self.assertEqual(response.status_code, 200)
        graph = response.get_json()
        self.assertEqual(graph["suppressed_common_indicators"], 1)
        self.assertEqual(graph["links"], [])


if __name__ == "__main__":
    unittest.main()
