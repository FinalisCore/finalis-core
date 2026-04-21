# SPDX-License-Identifier: MIT

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


class MintPackagingTests(unittest.TestCase):
    def test_systemd_units_reference_env_file(self) -> None:
        root = Path(__file__).parent / "systemd"
        server_unit = (root / "finalis-mint-server.service").read_text(encoding="utf-8")
        worker_unit = (root / "finalis-mint-worker.service").read_text(encoding="utf-8")
        self.assertIn("EnvironmentFile=-/etc/finalis-mint/finalis-mint.env", server_unit)
        self.assertIn("EnvironmentFile=-/etc/finalis-mint/finalis-mint.env", worker_unit)
        self.assertIn("--mode server", server_unit)
        self.assertIn("--mode worker", worker_unit)

    def test_install_script_installs_helper_and_tmpfiles(self) -> None:
        root = Path(__file__).parent / "systemd"
        install_script = (root / "install_finalis_mint.sh").read_text(encoding="utf-8")
        self.assertIn("finalis-mint-secret-helper", install_script)
        self.assertIn("finalis-mint.tmpfiles.conf", install_script)
        self.assertIn("finalis-mint.env", install_script)

    def test_env_template_exposes_secret_helper(self) -> None:
        root = Path(__file__).parent / "systemd"
        env_text = (root / "finalis-mint.env.example").read_text(encoding="utf-8")
        self.assertIn("FINALIS_MINT_NOTIFIER_SECRET_HELPER_CMD=/usr/local/libexec/finalis-mint-secret-helper", env_text)
        self.assertIn("FINALIS_MINT_WORKER_LOCK_FILE=", env_text)

    def test_install_script_smoke_to_temp_prefix(self) -> None:
        root = Path(__file__).parent / "systemd"
        script = root / "install_finalis_mint.sh"
        repo_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as td:
            systemd_dir = Path(td) / "systemd"
            etc_dir = Path(td) / "etc" / "finalis-mint"
            libexec_dir = Path(td) / "libexec"
            state_dir = Path(td) / "var" / "lib" / "finalis-mint"
            run_dir = Path(td) / "run" / "finalis-mint"
            proc = subprocess.run(
                ["bash", str(script), "/opt/finalis-core", str(systemd_dir), str(etc_dir), str(libexec_dir), str(state_dir), str(run_dir)],
                cwd=repo_root,
                check=True,
                text=True,
                capture_output=True,
            )
            self.assertIn("Installed unit files into", proc.stdout)
            self.assertTrue((systemd_dir / "finalis-mint-server.service").exists())
            self.assertTrue((systemd_dir / "finalis-mint-worker.service").exists())
            self.assertTrue((etc_dir / "finalis-mint.env").exists())
            self.assertTrue((etc_dir / "finalis-mint.tmpfiles.conf").exists())
            self.assertTrue((libexec_dir / "finalis-mint-secret-helper").exists())
            self.assertTrue(state_dir.exists())
            self.assertTrue(run_dir.exists())

    def test_smoke_deploy_quotes_helper_command_in_env_file(self) -> None:
        script = (Path(__file__).parent / "systemd" / "smoke_deploy.sh").read_text(encoding="utf-8")
        self.assertIn(
            'FINALIS_MINT_NOTIFIER_SECRET_HELPER_CMD="$ROOT/services/finalis-mint/secret_helper.py --dir $SECRETS_DIR --env-prefix FINALIS_MINT_SECRET_"',
            script,
        )


if __name__ == "__main__":
    unittest.main()
