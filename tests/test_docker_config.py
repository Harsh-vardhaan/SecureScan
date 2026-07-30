"""Static tests for the Phase 8 Docker deployment foundation.

These tests inspect configuration text only. They do not invoke Docker or Nmap.
"""

from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TestDockerConfiguration(unittest.TestCase):

    def test_dockerfile_has_test_and_non_root_runtime_stages(self):
        dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

        self.assertIn("FROM base AS test", dockerfile)
        self.assertIn("FROM base AS runtime", dockerfile)
        self.assertIn("apt-get install --yes --no-install-recommends nmap", dockerfile)
        self.assertIn("python -m unittest discover", dockerfile)
        self.assertIn("USER securescan", dockerfile)
        self.assertIn('"--workers", "1"', dockerfile)
        self.assertIn("backend.app:app", dockerfile)
        self.assertNotIn("privileged", dockerfile.lower())

    def test_compose_uses_localhost_volume_secret_and_runtime_target(self):
        compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")

        self.assertIn("target: runtime", compose)
        self.assertIn('"127.0.0.1:5000:5000"', compose)
        self.assertIn("${SECRET_KEY:?", compose)
        self.assertIn("securescan-data:/app/data", compose)
        self.assertIn("SECURESCAN_DATABASE_PATH: /app/data/securescan.db", compose)
        self.assertNotIn("privileged:", compose)
        self.assertNotIn("network_mode: host", compose)
        self.assertNotIn("/var/run/docker.sock", compose)

    def test_dockerignore_excludes_local_state_but_keeps_schema(self):
        dockerignore = (PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8")

        for expected in (".git", ".venv", ".env", "database/*.db", "*.pdf"):
            self.assertIn(expected, dockerignore)
        self.assertNotIn("database/schema.sql", dockerignore)
        self.assertNotIn("requirements.txt", dockerignore)

    def test_requirements_file_is_utf8_and_pins_runtime_server(self):
        requirements = (PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8")

        self.assertIn("gunicorn==", requirements)
        self.assertIn("reportlab==4.4.3", requirements)


if __name__ == "__main__":
    unittest.main()
