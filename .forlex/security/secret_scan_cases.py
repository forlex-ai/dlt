"""Behavioral tests for the secret gate; no live credential is used."""

import hashlib
import importlib.util
import io
import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

__all__ = ["io", "secrets", "string", "unittest"]


def gate():
    """Load the actual implementation or report the missing feature."""
    source = Path(__file__).with_name("secret_scan.py")
    if not source.exists():
        raise AssertionError("The approved fail-closed TruffleHog gate is not implemented")
    spec = importlib.util.spec_from_file_location("secret_scan", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def finding(raw="unit-only-value", *, verified=False, error=None, path="tests/unit/example.py"):
    """Build synthetic scanner output for protocol tests."""
    row = {
        "SourceMetadata": {"Data": {"Git": {"commit": "a" * 40, "file": path, "line": 7}}},
        "DetectorName": "Postgres",
        "Raw": raw,
        "RawV2": "",
        "Verified": verified,
    }
    if error is not None:
        row["VerificationError"] = error
    return row


def exception(row):
    """Build one exact exception for a synthetic finding."""
    result = {
        "id": "unit-fixture-1",
        "repository": "forlex-ai/unit",
        "detector": row["DetectorName"],
        "path": row["SourceMetadata"]["Data"]["Git"]["file"],
        "commit": "a" * 40,
        "fingerprint": hashlib.sha256(row["Raw"].encode()).hexdigest(),
        "owner": "danielbichuetti",
        "rationale": "Reviewed synthetic fixture, no live credential.",
        "expires": "2099-01-01",
    }
    result["proof"] = proof_url(result)
    return result


def proof_url(row):
    """Reference the exact inert fixture source, without a live proof fetch."""
    return (
        "https://github.com/"
        + row["repository"]
        + "/blob/"
        + row["commit"]
        + "/"
        + urllib.parse.quote(row["path"], safe="/")
    )


def pr_api_fixture(module):
    """Provide independently defined live GitHub facts and inspect every check write."""
    repository = "forlex-ai/unit"
    head = "a" * 40
    base = "b" * 40
    merge = "c" * 40
    responses = {
        "": {"full_name": repository, "default_branch": "main"},
        "pulls/1": {
            "state": "open",
            "head": {"sha": head},
            "base": {"ref": "test", "sha": "d" * 40, "repo": {"full_name": repository}},
            "merge_commit_sha": merge,
            "mergeable": True,
        },
        "git/ref/heads/test": {"ref": "refs/heads/test", "object": {"type": "commit", "sha": base}},
        "git/commits/" + merge: {"sha": merge, "parents": [{"sha": base}, {"sha": head}]},
    }
    checks = {}
    calls = []

    def api(repo, suffix, *, method="GET", body=None):
        calls.append((method, suffix, body))
        assert repo == repository
        if method == "POST":
            number = 3 + len(checks)
            result = {
                "id": number,
                "head_sha": body["head_sha"],
                "name": body["name"],
                "app": {"id": 15368},
                "status": body["status"],
            }
            checks["check-runs/" + str(number)] = result
            return result
        if suffix in checks:
            if method == "PATCH":
                checks[suffix] = {**checks[suffix], **body}
            return checks[suffix]
        if suffix not in responses:
            raise module.SecretScanRefusal("Unavailable synthetic API fact")
        return responses[suffix]

    module.github = api
    event = {
        "number": 1,
        "repository": {"full_name": repository},
        "pull_request": {"head": {"sha": head}, "base": {"ref": "test", "sha": "d" * 40}},
    }
    return event, responses, checks, calls


class _GateMoreCases:
    def test_pr_context_uses_current_base_ref_and_binds_both_evaluated_commits(self):
        """A cached Pulls API base cannot select obsolete qualification history."""
        module = gate()
        event, responses, checks, calls = pr_api_fixture(module)
        source = module.context(event, "pull_request_target", "forlex-ai/unit")
        self.assertEqual(source["base"], "b" * 40)
        self.assertEqual(source["base_ref"], "test")
        self.assertEqual(source["merge"], "c" * 40)
        self.assertEqual(source["check_id"], 3)
        self.assertEqual(source["merge_check_id"], 4)
        self.assertEqual([c["head_sha"] for c in checks.values()], ["a" * 40, "c" * 40])
        self.assertIn(("GET", "git/ref/heads/test", None), calls)

    def test_unaccepted_base_and_wrong_prospective_parents_cannot_create_checks(self):
        """Auxiliary bases and stale/foreign merge results refuse before check creation."""
        for changed in ["auxiliary", "parent", "reverse", "missing_merge", "bad_ref"]:
            module = gate()
            event, responses, checks, calls = pr_api_fixture(module)
            if changed == "auxiliary":
                responses["pulls/1"]["base"]["ref"] = "topic"
            elif changed == "parent":
                responses["git/commits/" + "c" * 40]["parents"][1]["sha"] = "e" * 40
            elif changed == "reverse":
                responses["git/commits/" + "c" * 40]["parents"].reverse()
            elif changed == "missing_merge":
                responses["pulls/1"]["merge_commit_sha"] = None
            else:
                responses["git/ref/heads/test"]["object"]["type"] = "tag"
            with self.assertRaises(ValueError):
                module.context(event, "pull_request_target", "forlex-ai/unit")
            self.assertFalse(checks)
            self.assertFalse(any(method == "POST" for method, _, _ in calls))

    def test_context_cli_outputs_merge_and_accepts_manifest_integration_branch(self):
        """The owning manifest branch can replace the common test default explicitly."""
        module = gate()
        event, responses, checks, calls = pr_api_fixture(module)
        responses["pulls/1"]["base"]["ref"] = "release"
        responses["git/ref/heads/release"] = {
            **responses.pop("git/ref/heads/test"),
            "ref": "refs/heads/release",
        }
        event["pull_request"]["base"]["ref"] = "release"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ep = root / "event"
            output = root / "context"
            gha = root / "output"
            ep.write_text(json.dumps(event))
            argv = [
                "secret_scan.py",
                "context",
                "--event",
                str(ep),
                "--kind",
                "pull_request_target",
                "--repository",
                "forlex-ai/unit",
                "--integration-branch",
                "release",
                "--output",
                str(output),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.dict(os.environ, {"GITHUB_OUTPUT": str(gha)}),
            ):
                self.assertEqual(module.main(), 0)
            self.assertIn("merge=" + "c" * 40 + "\n", gha.read_text())
            self.assertEqual(json.loads(output.read_text())["integration_branch"], "release")

    def test_dual_check_publication_requires_current_ref_merge_and_trusted_candidate_parse(self):
        """Both immutable check targets complete only for the same qualified prospective result."""
        for changed in [None, "base", "head", "merge", "report_merge", "candidate_unvalidated"]:
            module = gate()
            event, responses, checks, calls = pr_api_fixture(module)
            source = module.context(event, "pull_request_target", "forlex-ai/unit")
            report = {
                **source,
                "version": 1,
                "result": "pass",
                "blocked": 0,
                "suppressed": 0,
                "commit_count": 3,
                "candidate_policy_validated": True,
                "candidate_policy_source": source["merge"],
                "candidate_policy_blob": "f" * 40,
            }
            if changed == "base":
                responses["git/ref/heads/test"]["object"]["sha"] = "e" * 40
            elif changed == "head":
                responses["pulls/1"]["head"]["sha"] = "e" * 40
            elif changed == "merge":
                responses["pulls/1"]["merge_commit_sha"] = "e" * 40
            elif changed == "report_merge":
                report["merge"] = "e" * 40
            elif changed == "candidate_unvalidated":
                report.pop("candidate_policy_validated")
            result = module.publish(source, report)
            expected = "success" if changed is None else "failure"
            self.assertEqual(result["conclusion"], expected)
            self.assertEqual([c["conclusion"] for c in checks.values()], [expected, expected])
            self.assertEqual(
                [s for method, s, _ in calls if method == "PATCH"], ["check-runs/3", "check-runs/4"]
            )

    def test_foreign_prospective_check_refuses_success_and_fails_only_verified_head(self):
        """A foreign merge check remains untouched while the verified original head fails safely."""
        module = gate()
        event, _responses, checks, calls = pr_api_fixture(module)
        source = module.context(event, "pull_request_target", "forlex-ai/unit")
        checks["check-runs/4"]["app"]["id"] = 46505
        report = {
            **source,
            "version": 1,
            "result": "pass",
            "blocked": 0,
            "suppressed": 0,
            "commit_count": 3,
            "candidate_policy_validated": True,
            "candidate_policy_source": source["merge"],
            "candidate_policy_blob": "f" * 40,
        }
        with self.assertRaises(ValueError):
            module.publish(source, report)
        self.assertEqual(
            [(suffix, body["conclusion"]) for method, suffix, body in calls if method == "PATCH"],
            [("check-runs/3", "failure")],
        )
        self.assertEqual(checks["check-runs/3"]["status"], "completed")
        self.assertEqual(checks["check-runs/4"]["status"], "in_progress")

    def test_base_moving_between_dual_writes_downgrades_both_original_checks(self):
        """A successful first write cannot remain qualified after live source changes."""
        module = gate()
        event, responses, checks, calls = pr_api_fixture(module)
        source = module.context(event, "pull_request_target", "forlex-ai/unit")
        api = module.github

        def racing(repo, suffix, *, method="GET", body=None):
            result = api(repo, suffix, method=method, body=body)
            if method == "PATCH" and suffix == "check-runs/3" and body["conclusion"] == "success":
                responses["git/ref/heads/test"]["object"]["sha"] = "e" * 40
            return result

        module.github = racing
        report = {
            **source,
            "version": 1,
            "result": "pass",
            "blocked": 0,
            "suppressed": 0,
            "commit_count": 3,
            "candidate_policy_validated": True,
            "candidate_policy_source": source["merge"],
            "candidate_policy_blob": "f" * 40,
        }
        result = module.publish(source, report)
        self.assertEqual(result["conclusion"], "failure")
        self.assertEqual([check["conclusion"] for check in checks.values()], ["failure", "failure"])

    def test_candidate_policy_is_parsed_from_regular_git_data_without_following_symlinks(self):
        """Candidate executable helpers and symlink policy targets cannot run or change authority."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            path = repo / ".forlex/security"
            path.mkdir(parents=True)
            marker = root / "executed"
            outside = root / "outside-policy"
            outside.write_text('{"version":1,"exceptions":[]}')
            (path / "secret_scan.py").write_text(
                "open(" + repr(str(marker)) + ',"w").write("executed")\n'
            )
            target = path / "exceptions.json"

            def commit():
                subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "-c",
                        "user.name=Unit",
                        "-c",
                        "user.email=unit@example.invalid",
                        "commit",
                        "-qm",
                        "policy",
                    ],
                    check=True,
                )
                return subprocess.check_output(
                    ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
                ).strip()

            target.write_text('{"version":1,"exceptions":[]}')
            head = commit()
            self.assertTrue(gate().validate_candidate_policy(repo, head))
            target.write_text('{"version":1,"version":1,"exceptions":[]}')
            head = commit()
            with self.assertRaises(ValueError):
                gate().validate_candidate_policy(repo, head)
            target.unlink()
            target.symlink_to(outside)
            head = commit()
            with self.assertRaises(ValueError):
                gate().validate_candidate_policy(repo, head)
            self.assertFalse(marker.exists())
            self.assertEqual(outside.read_text(), '{"version":1,"exceptions":[]}')

    def test_scan_cli_requires_prospective_candidate_policy_but_allows_prepolicy_history(self):
        """PR acceptance validates proposed rules; old historical/tag data keeps trusted rules."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)

            def git(*args):
                return subprocess.check_output(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "-c",
                        "user.name=Unit",
                        "-c",
                        "user.email=unit@example.invalid",
                        *args,
                    ],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()

            git("commit", "--allow-empty", "-qm", "initial")
            ancestor = git("rev-parse", "HEAD")
            git("checkout", "-qb", "feature")
            (repo / "feature").write_text("clean candidate")
            git("add", ".")
            git("commit", "-qm", "feature")
            head = git("rev-parse", "HEAD")
            git("checkout", "-qb", "accepted", ancestor)
            (repo / "base").write_text("clean accepted")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            git("merge", "--no-ff", "-qm", "prospective", "feature")
            merge = git("rev-parse", "HEAD")
            marker = root / "scanner-called"
            scanner = root / "scanner"
            scanner.write_text(
                "#!/usr/bin/env python3\nfrom pathlib import Path\nPath("
                + repr(str(marker))
                + ').write_text("called")\n'
            )
            scanner.chmod(0o700)
            policy = root / "accepted-policy"
            policy.write_text('{"version":1,"exceptions":[]}')
            context = root / "context"
            output = root / "report"
            command = [
                "secret_scan.py",
                "scan",
                "--repo",
                str(repo),
                "--scanner",
                str(scanner),
                "--policy",
                str(policy),
                "--context",
                str(context),
                "--output",
                str(output),
            ]
            context.write_text(
                json.dumps(
                    {
                        "repository": "forlex-ai/unit",
                        "pr": 1,
                        "head": head,
                        "base": base,
                        "merge": merge,
                        "kind": "pull_request_target",
                    }
                )
            )
            with patch.object(sys, "argv", command):
                self.assertEqual(gate().main(), 1)
            self.assertFalse(marker.exists())
            self.assertEqual(json.loads(output.read_text())["result"], "error")
            context.write_text(
                json.dumps(
                    {
                        "repository": "forlex-ai/unit",
                        "pr": None,
                        "head": ancestor,
                        "base": None,
                        "kind": "schedule",
                    }
                )
            )
            with patch.object(sys, "argv", command):
                self.assertEqual(gate().main(), 0)
            self.assertTrue(marker.exists())
            self.assertEqual(json.loads(output.read_text())["result"], "pass")

    def test_proof_must_bind_immutable_repository_commit_and_path(self):
        """An exception cannot cite another source, a branch, or a mutable proof URL."""
        row = exception(finding())
        row["proof"] = "https://github.com/forlex-ai/unit/blob/" + row["commit"] + "/" + row["path"]
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps({"version": 1, "exceptions": [row]}))
            self.assertEqual(gate().read_policy(policy), [row])
            for proof in (
                row["proof"].replace("/unit/", "/other/"),
                row["proof"].replace(row["commit"], "main"),
                row["proof"].replace(row["commit"], "b" * 40),
                row["proof"] + "?raw=1",
                row["proof"] + "#line",
                row["proof"].replace("https://", "http://"),
                row["proof"].replace("/tests/", "/elsewhere/"),
            ):
                policy.write_text(
                    json.dumps({"version": 1, "exceptions": [{**row, "proof": proof}]})
                )
                with self.assertRaises(ValueError):
                    gate().read_policy(policy)

    def test_json_writes_explicitly_label_the_request_body(self):
        """Checks API writes carry JSON content type and reads stay credential scoped."""
        module = gate()
        requests = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b"{}"

        def send(request, **kwargs):
            requests.append(request)
            return Response()

        with (
            patch.dict(os.environ, {"GH_TOKEN": "inert-unit-auth"}),
            patch.object(module.urllib.request, "urlopen", send),
        ):
            module.github("forlex-ai/unit", "check-runs", method="POST", body={"name": "unit"})
            module.github(
                "forlex-ai/unit", "check-runs/3", method="PATCH", body={"status": "completed"}
            )
            module.github("forlex-ai/unit", "pulls/1")
        self.assertTrue(
            all(r.get_header("Content-type") == "application/json" for r in requests[:2])
        )
        self.assertIsNone(requests[2].data)

    def test_live_output_bounds_stop_both_streams_and_cleanup_the_process_group(self):
        """Refuse producers while they write, including a child retaining pipe descriptors."""
        module = gate()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for stream in ["stdout", "stderr"]:
                output = root / (stream + "-out")
                errors = root / (stream + "-err")
                sentinel = root / (stream + "-survived")
                body = (
                    "import os,sys,time\nif os.fork()==0:\n time.sleep(0.5)\n"
                    " open(sys.argv[1],'w').write('survived')\n os._exit(0)\n"
                )
                body += (
                    "stream=sys."
                    + stream
                    + ".buffer\nwhile True:\n stream.write(b'x'*4096);stream.flush()\n"
                )
                started = time.monotonic()
                with self.assertRaises(ValueError):
                    module.run_bounded_scanner(
                        [sys.executable, "-c", body, str(sentinel)],
                        os.environ.copy(),
                        output,
                        errors,
                        time.monotonic() + 4,
                        output_limit=8192,
                        error_limit=8192,
                    )
                self.assertLess(time.monotonic() - started, 2)
                self.assertLessEqual(output.stat().st_size, 8192)
                self.assertLessEqual(errors.stat().st_size, 8192)
                time.sleep(0.6)
                self.assertFalse(sentinel.exists(), "Scanner child survived refusal")

    def test_rewind_range_rescans_reachable_history(self):
        """A backwards branch update cannot claim an empty clean range."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Unit",
                    "-c",
                    "user.email=unit@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "first",
                ],
                check=True,
            )
            head = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Unit",
                    "-c",
                    "user.email=unit@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "later",
                ],
                check=True,
            )
            before = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            effective, commits = gate().git_range(repo, head, before)
            self.assertIsNone(effective)
            self.assertEqual(commits, [head])

    def test_nonforward_push_with_unrelated_history_scans_the_complete_new_head(self):
        """A rewritten branch with no merge base retains complete replacement coverage."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)

            def commit(message):
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "-c",
                        "user.name=Unit",
                        "-c",
                        "user.email=unit@example.invalid",
                        "commit",
                        "--allow-empty",
                        "-qm",
                        message,
                    ],
                    check=True,
                )
                return subprocess.check_output(
                    ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
                ).strip()

            before = commit("old history")
            subprocess.run(
                ["git", "-C", str(repo), "checkout", "--orphan", "replacement"],
                check=True,
                capture_output=True,
            )
            first = commit("new root")
            head = commit("new tip")
            effective, commits = gate().git_range(repo, head, before, full_if_nonforward=True)
            self.assertIsNone(effective)
            self.assertEqual(commits, [head, first])

    def test_all_detection_states_block_by_default(self):
        """Verify all detection states block by default."""
        for row in (finding(), finding(verified=True), finding(error="verification unavailable")):
            with self.subTest(verified=row["Verified"]):
                self.assertFalse(gate().classify(row, [], "forlex-ai/unit")["suppressed"])

    def test_test_directories_are_scanned(self):
        """Verify test directories are scanned."""
        row = finding(path="tests/unit/new_secret.py")
        self.assertFalse(gate().classify(row, [], "forlex-ai/unit")["suppressed"])

    def test_exception_requires_exact_value_detector_path_commit_and_repo(self):
        """Verify exception requires exact value detector path commit and repo."""
        row = finding()
        rule = exception(row)
        self.assertTrue(gate().classify(row, [rule], "forlex-ai/unit")["suppressed"])
        for key, value in (
            ("path", "tests/unit/elsewhere.py"),
            ("detector", "GitHub"),
            ("commit", "b" * 40),
            ("fingerprint", "0" * 64),
            ("repository", "forlex-ai/another"),
        ):
            changed = {**rule, key: value}
            self.assertFalse(gate().classify(row, [changed], "forlex-ai/unit")["suppressed"])

    def test_verified_detection_cannot_be_suppressed(self):
        """Verify verified detection cannot be suppressed."""
        row = finding(verified=True)
        self.assertFalse(gate().classify(row, [exception(row)], "forlex-ai/unit")["suppressed"])

    def test_expired_exception_does_not_allow_a_finding(self):
        """Verify expired exception does not allow a finding."""
        row = finding()
        rule = {**exception(row), "expires": "2000-01-01"}
        self.assertFalse(gate().classify(row, [rule], "forlex-ai/unit")["suppressed"])

    def test_report_omits_raw_redacted_error_and_fingerprints(self):
        """Verify report omits raw redacted error and fingerprints."""
        raw = "never-print-this-synthetic-test-value"
        row = finding(raw, error=raw)
        row["Redacted"] = raw
        output = json.dumps(gate().classify(row, [], "forlex-ai/unit"))
        self.assertNotIn(raw, output)
        self.assertNotIn(hashlib.sha256(raw.encode()).hexdigest(), output)
        self.assertNotIn("VerificationError", output)

    def test_secret_in_filename_is_not_published(self):
        """Never publish credential bytes carried in Git path metadata."""
        raw = "synthetic-path-credential"
        row = finding(raw, path="tests/" + raw + ".py")
        result = gate().classify(row, [], "forlex-ai/unit")
        self.assertNotIn(raw, json.dumps(result))
        self.assertEqual(
            result["path_digest"],
            hashlib.sha256(row["SourceMetadata"]["Data"]["Git"]["file"].encode()).hexdigest(),
        )

    def test_missing_or_invalid_finding_fields_fail_closed(self):
        """Verify missing or invalid finding fields fail closed."""
        for row in (
            {},
            {**finding(), "Raw": ""},
            {**finding(), "Verified": "false"},
            {**finding(), "SourceMetadata": {"Data": {"Git": {"commit": "HEAD"}}}},
        ):
            with self.assertRaises(ValueError):
                gate().classify(row, [], "forlex-ai/unit")

    def test_duplicate_json_keys_are_refused(self):
        """Verify duplicate json keys are refused."""
        with self.assertRaises(ValueError):
            gate().strict_json('{"Raw":"first","Raw":"second"}')

    def test_exception_policy_requires_all_explicit_fields(self):
        """Verify exception policy requires all explicit fields."""
        row = exception(finding())
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps({"version": 1, "exceptions": [row]}))
            self.assertEqual(gate().read_policy(policy), [row])
            for key in row:
                policy.write_text(
                    json.dumps(
                        {"version": 1, "exceptions": [{k: v for k, v in row.items() if k != key}]}
                    )
                )
                with self.assertRaises(ValueError):
                    gate().read_policy(policy)

    def test_validate_policy_cli_uses_strict_policy_and_redacts_rejections(self):
        """Validate the actual candidate policy without publishing rejected field values."""
        secret = "sensitive-policy-authority"
        rule = exception(finding())
        invalid = (
            "{",
            '{"version":1,"version":1,"exceptions":[]}',
            json.dumps({"version": 2, "exceptions": []}),
            json.dumps({"version": 1, "exceptions": [{**rule, "owner": secret}]}),
            json.dumps({"version": 1, "exceptions": [rule, rule]}),
        )
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            command = [
                sys.executable,
                str(Path(__file__).with_name("secret_scan.py")),
                "validate-policy",
                "--policy",
                str(policy),
            ]
            for body in invalid:
                with self.subTest(body=body):
                    policy.write_text(body)
                    result = subprocess.run(command, capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn(secret, result.stdout + result.stderr)
            policy.write_text(json.dumps({"version": 1, "exceptions": [rule]}))
            self.assertEqual(
                subprocess.run(command, capture_output=True, check=False).returncode, 0
            )

    def test_scanner_error_and_invalid_output_fail_and_never_expose_output(self):
        """Verify scanner error and invalid output fail and never expose output."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Unit",
                    "-c",
                    "user.email=unit@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "initial",
                ],
                check=True,
            )
            head = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            scanner = root / "scanner"
            for body in (
                "print('sensitive-but-synthetic-output'); raise SystemExit(1)",
                "print('invalid-json')",
                (
                    "import sys;"
                    ' print(\'{"level":"error","message":"sensitive-but-synthetic-output"}\','
                    " file=sys.stderr)"
                ),
                "import sys; print('unparsed-sensitive-diagnostic', file=sys.stderr)",
            ):
                scanner.write_text("#!/usr/bin/env python3\n" + body + "\n")
                scanner.chmod(0o700)
                result = gate().scan(repo, head, None, scanner, policy, "forlex-ai/unit", 10)
                self.assertEqual(result["result"], "error")
                self.assertNotIn("sensitive-but-synthetic-output", json.dumps(result))
                self.assertEqual(list(root.glob("trufflehog-raw*")), [])

    def test_missing_commit_and_shallow_history_are_refused(self):
        """Verify missing commit and shallow history are refused."""
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            gate().git_range(Path(directory), "a" * 40, None)
