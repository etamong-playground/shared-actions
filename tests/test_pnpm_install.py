import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/pnpm-install"


class PnpmInstall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.steps = json.loads(subprocess.check_output([
            "ruby", "-rjson", "-ryaml", "-e",
            "puts JSON.generate(YAML.safe_load(File.read(ARGV.fetch(0)), aliases:false))",
            str(ACTION / "action.yml"),
        ], text=True))["runs"]["steps"]

    def setUp(self):
        scratch = ROOT / ".tmp"
        scratch.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / "home"
        self.runner = self.root / "runner temp"
        self.project = self.root / "project with spaces"
        self.bin = self.root / "bin"
        for path in (self.home, self.runner, self.project, self.bin):
            path.mkdir()
        self.config = self.home / ".npmrc"
        self.original = "registry=https://registry.example/\nother-setting=preserved\n"
        self.config.write_text(self.original)
        self.record = self.root / "record.json"
        (self.bin / "corepack").write_text("#!/bin/sh\nexit 0\n")
        (self.bin / "corepack").chmod(0o700)
        (self.bin / "pnpm").write_text(f"#!{sys.executable}\n" + '''
import json, os, pathlib, stat, sys, time
config = pathlib.Path(os.environ.get("NPM_CONFIG_USERCONFIG", os.environ.get("npm_config_userconfig", str(pathlib.Path.home() / ".npmrc"))))
body = config.read_text() if config.exists() else ""
record = {"path": str(config), "mode": stat.S_IMODE(config.stat().st_mode), "body": body, "args": sys.argv[1:], "cwd": os.getcwd()}
output = pathlib.Path(os.environ["INSTALL_RECORD"])
pending = output.with_suffix(".pending")
pending.write_text(json.dumps(record))
pending.replace(output)
if os.environ.get("INSTALL_WAIT") == "1":
    while True:
        time.sleep(0.05)
sys.exit(int(os.environ.get("INSTALL_EXIT", "0")))
''')
        (self.bin / "pnpm").chmod(0o700)
        self.inputs = {
            "working-directory": str(self.project),
            "registry-url": "https://packages.example/team/",
            "scope": "@example",
            "npm-token": "controlled-install-token",
        }
        self.env = {key: value for key, value in os.environ.items() if key.lower() not in {
            "npm_config_userconfig", "npm_token", "node_auth_token", "registry_url", "scope",
        }}
        self.env.update({
            "HOME": str(self.home),
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "RUNNER_TEMP": str(self.runner),
            "GITHUB_ACTION_PATH": str(ACTION),
            "INSTALL_RECORD": str(self.record),
        })

    def step_env(self, step):
        env = self.env.copy()
        for key, value in step.get("env", {}).items():
            match = re.fullmatch(r"\$\{\{\s*inputs\.([\w-]+)\s*\}\}", value)
            env[key] = self.inputs[match.group(1)] if match else value
        return env

    def step_script(self, step):
        path = self.root / "step.sh"
        path.write_text(step["run"])
        return str(path)

    def run_action(self):
        for step in self.steps:
            result = subprocess.run(
                ["bash", "-e", "-o", "pipefail", self.step_script(step)],
                env=self.step_env(step), cwd=self.project, capture_output=True, text=True,
            )
            if result.returncode:
                return result
        return result

    def assert_clean(self, original=None):
        self.assertEqual(self.config.read_text(), self.original if original is None else original)
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_success_preserves_user_config_and_removes_install_credentials(self):
        result = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_clean()
        record = json.loads(self.record.read_text())
        self.assertEqual(record["mode"], 0o600)
        self.assertNotEqual(Path(record["path"]), self.config)
        self.assertFalse(Path(record["path"]).exists())
        self.assertIn(self.original, record["body"])
        self.assertIn("@example:registry=https://packages.example/team/", record["body"])
        self.assertIn('//packages.example/team/:_authToken="controlled-install-token"', record["body"])
        self.assertEqual(record["args"], ["install", "--frozen-lockfile", "--ignore-scripts"])
        self.assertEqual(Path(record["cwd"]), self.project)
        self.assertNotIn(self.inputs["npm-token"], result.stdout + result.stderr)

    def test_failure_preserves_status_and_cleans_credentials(self):
        self.env["INSTALL_EXIT"] = "23"
        result = self.run_action()
        self.assertEqual(result.returncode, 23)
        self.assert_clean()
        self.assertFalse(Path(json.loads(self.record.read_text())["path"]).exists())

    def test_selected_user_configuration_is_preserved_and_available(self):
        custom = self.root / "custom config"
        custom.write_text("custom-setting=preserved\n")
        self.env["NPM_CONFIG_USERCONFIG"] = str(custom)
        result = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_clean()
        self.assertEqual(custom.read_text(), "custom-setting=preserved\n")
        self.assertIn("custom-setting=preserved", json.loads(self.record.read_text())["body"])

    def test_missing_user_config_is_not_created(self):
        self.config.unlink()
        result = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.config.exists())
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_lowercase_config_selection_and_missing_final_newline(self):
        custom = self.root / "custom config"
        custom.write_text("custom-setting=preserved")
        self.env["npm_config_userconfig"] = str(custom)
        self.inputs["registry-url"] = "http://packages.example:8080/team"
        result = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_clean()
        record = json.loads(self.record.read_text())
        self.assertIn("custom-setting=preserved\n", record["body"])
        self.assertIn('//packages.example:8080/team/:_authToken="controlled-install-token"', record["body"])
        self.assertEqual(custom.read_text(), "custom-setting=preserved")

    def test_token_is_quoted_without_losing_special_characters(self):
        self.inputs["npm-token"] = ' abc#def;"quoted"\\tail '
        result = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        body = json.loads(self.record.read_text())["body"]
        auth = next(line.split("=", 1)[1] for line in body.splitlines() if ":_authToken=" in line)
        self.assertEqual(json.loads(auth), self.inputs["npm-token"])
        self.assert_clean()

    def test_repeated_installs_use_distinct_private_files(self):
        paths = []
        for _ in range(2):
            self.assertEqual(self.run_action().returncode, 0)
            paths.append(json.loads(self.record.read_text())["path"])
            self.assert_clean()
        self.assertNotEqual(paths[0], paths[1])

    def assert_interrupt_cleanup(self, signum):
        self.env["INSTALL_WAIT"] = "1"
        for step in self.steps[:-1]:
            result = subprocess.run(["bash", "-e", self.step_script(step)], env=self.step_env(step), cwd=self.project, capture_output=True)
            self.assertEqual(result.returncode, 0)
        step = self.steps[-1]
        process = subprocess.Popen(["bash", "-e", self.step_script(step)], env=self.step_env(step), cwd=self.project, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not self.record.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(self.record.exists(), "fixture install did not start")
            os.kill(process.pid, signum)
            process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0)
            self.assert_clean()
            self.assertFalse(Path(json.loads(self.record.read_text())["path"]).exists())
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()

    def test_termination_cleans_the_private_configuration(self):
        self.assert_interrupt_cleanup(signal.SIGTERM)

    def test_interrupt_cleans_the_private_configuration(self):
        self.assert_interrupt_cleanup(signal.SIGINT)

    def test_rejects_invalid_inputs_without_echoing_credentials(self):
        cases = {
            "registry-url": ["", "file:///registry", "https://user:password@packages.example/", "https://packages.example/?key=value", "https://packages.example/#fragment", "https://packages.example/\nregistry=https://other.example/"],
            "scope": ["", "example", "@example\nregistry=https://other.example/"],
            "npm-token": ["", "controlled-install-token\nother=value", "controlled-install-token\rother=value"],
        }
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    original = self.inputs[key]
                    self.inputs[key] = value
                    result = self.run_action()
                    self.inputs[key] = original
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("controlled-install-token", result.stdout + result.stderr)
                    self.assertFalse(self.record.exists())
                    self.assert_clean()


if __name__ == "__main__":
    unittest.main()
