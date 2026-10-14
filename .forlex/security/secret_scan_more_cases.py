"""Additional unchanged protocol cases; discovered through GateTests only."""

from secret_scan_cases import (
    Path,
    gate,
    io,
    json,
    os,
    patch,
    pr_api_fixture,
    subprocess,
    sys,
    tempfile,
)


class _GateFinalCases:
    def test_context_cli_persistence_errors_fail_all_acknowledged_owned_checks(self):
        """Local context/output write or close failures cannot strand created checks."""
        for kind in ("pull_request_target", "push"):
            for fault in (
                "context",
                "github_output",
                "missing_output",
                "stream_write",
                "stream_close",
            ):
                with self.subTest(kind=kind, fault=fault):
                    module = gate()
                    event, responses, checks, calls = pr_api_fixture(module)
                    event["before"] = "b" * 40
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        ep, output, gha = root / "event", root / "context", root / "gha"
                        ep.write_text(json.dumps(event))
                        if fault == "context":
                            output.mkdir()
                        elif fault == "github_output":
                            gha.mkdir()
                        argv = [
                            "secret_scan.py",
                            "context",
                            "--event",
                            str(ep),
                            "--kind",
                            kind,
                            "--repository",
                            "forlex-ai/unit",
                            "--output",
                            str(output),
                        ]

                        class FailingOutput(io.StringIO):
                            def write(self, value):
                                super().write(value)
                                if fault == "stream_write":
                                    raise OSError("private-context-write-marker")
                                return len(value)

                            def __exit__(self, *args):
                                if fault == "stream_close":
                                    raise OSError("private-context-write-marker")
                                return super().__exit__(*args)

                        stream = FailingOutput()
                        console = io.StringIO()
                        with (
                            patch.object(sys, "argv", argv),
                            patch.dict(
                                os.environ, {"GITHUB_OUTPUT": str(gha), "GITHUB_SHA": "a" * 40}
                            ),
                            patch("sys.stdout", console),
                        ):
                            if fault == "missing_output":
                                os.environ.pop("GITHUB_OUTPUT")
                            if fault in {"stream_write", "stream_close"}:
                                with patch.object(module, "open", return_value=stream, create=True):
                                    self.assertEqual(module.main(), 1)
                            else:
                                self.assertEqual(module.main(), 1)
                        self.assertNotIn("private-context-write-marker", console.getvalue())
                        self.assertNotIn("head=", console.getvalue())
                        self.assertNotIn('"check_id"', console.getvalue())
                    self.assertEqual(len(checks), 2 if kind == "pull_request_target" else 1)
                    self.assertTrue(
                        all(
                            check.get("conclusion") == "failure" and check["status"] == "completed"
                            for check in checks.values()
                        )
                    )
                    patches = [
                        (i, suffix, body)
                        for i, (method, suffix, body) in enumerate(calls)
                        if method == "PATCH"
                    ]
                    self.assertEqual(len(patches), len(checks))
                    for index, suffix, body in patches:
                        self.assertEqual(calls[index - 1], ("GET", suffix, None))
                        self.assertEqual(body["conclusion"], "failure")

    def test_context_persistence_cleanup_preserves_identity_and_continues_after_read_failure(self):
        """The CLI guard uses verified cleanup without letting one target block another."""
        for fault in ("foreign", "unavailable"):
            module = gate()
            event, responses, checks, calls = pr_api_fixture(module)
            api = module.github

            def failed_read(repo, suffix, *, method="GET", body=None):
                if method == "GET" and suffix == "check-runs/3":
                    if fault == "foreign":
                        checks[suffix]["app"]["id"] = 46505
                    else:
                        calls.append((method, suffix, body))
                        raise module.SecretScanRefusal("private-context-api-marker")
                return api(repo, suffix, method=method, body=body)

            module.github = failed_read
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ep, output, gha = root / "event", root / "context", root / "gha"
                ep.write_text(json.dumps(event))
                output.mkdir()
                argv = [
                    "secret_scan.py",
                    "context",
                    "--event",
                    str(ep),
                    "--kind",
                    "pull_request_target",
                    "--repository",
                    "forlex-ai/unit",
                    "--output",
                    str(output),
                ]
                console = io.StringIO()
                with (
                    patch.object(sys, "argv", argv),
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(gha)}),
                    patch("sys.stdout", console),
                ):
                    self.assertEqual(module.main(), 1)
                self.assertNotIn("private-context-api-marker", console.getvalue())
                self.assertFalse(gha.exists())
            self.assertEqual(checks["check-runs/3"]["status"], "in_progress")
            self.assertEqual(checks["check-runs/4"].get("conclusion"), "failure")
            self.assertEqual(
                [suffix for method, suffix, _ in calls if method == "PATCH"], ["check-runs/4"]
            )

    def test_second_context_creation_failure_closes_only_the_known_original_check(self):
        """An unacknowledged second POST cannot strand the acknowledged owned head."""
        for lost_ack in (False, True):
            module = gate()
            event, responses, checks, calls = pr_api_fixture(module)
            api = module.github
            posts = 0

            def failing(repo, suffix, *, method="GET", body=None):
                nonlocal posts
                if method == "POST":
                    posts += 1
                    if posts == 2:
                        if lost_ack:
                            api(repo, suffix, method=method, body=body)
                        else:
                            calls.append((method, suffix, body))
                        raise module.SecretScanRefusal("private-response-marker")
                return api(repo, suffix, method=method, body=body)

            module.github = failing
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ep, output, gha = root / "event", root / "context", root / "gha"
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
                    "--output",
                    str(output),
                ]
                console = io.StringIO()
                with (
                    patch.object(sys, "argv", argv),
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(gha)}),
                    patch("sys.stdout", console),
                ):
                    self.assertEqual(module.main(), 1)
                self.assertFalse(output.exists())
                self.assertFalse(gha.exists())
                self.assertNotIn("private-response-marker", console.getvalue())
            self.assertEqual(checks["check-runs/3"].get("conclusion"), "failure")
            self.assertEqual(checks["check-runs/3"]["status"], "completed")
            self.assertEqual(
                [suffix for method, suffix, _ in calls if method == "PATCH"], ["check-runs/3"]
            )
            if lost_ack:
                self.assertEqual(checks["check-runs/4"]["status"], "in_progress")

    def test_context_cleanup_cannot_mutate_foreign_or_unverifiable_checks(self):
        """Cleanup requires a fresh exact identity and never guesses an unknown POST id."""
        for changed in ("id", "head", "name", "app", "read_outage"):
            module = gate()
            event, responses, checks, calls = pr_api_fixture(module)
            api = module.github
            posts = 0

            def failing(repo, suffix, *, method="GET", body=None):
                nonlocal posts
                if method == "POST":
                    posts += 1
                    if posts == 2:
                        calls.append((method, suffix, body))
                        check = checks["check-runs/3"]
                        if changed == "id":
                            check["id"] = 3.0
                        elif changed == "head":
                            check["head_sha"] = "e" * 40
                        elif changed == "name":
                            check["name"] = "Other check"
                        elif changed == "app":
                            check["app"]["id"] = 15368.0
                        raise module.SecretScanRefusal("private-response-marker")
                if changed == "read_outage" and method == "GET" and suffix == "check-runs/3":
                    calls.append((method, suffix, body))
                    raise module.SecretScanRefusal("private-response-marker")
                return api(repo, suffix, method=method, body=body)

            module.github = failing
            with self.assertRaises(ValueError) as refused:
                module.context(event, "pull_request_target", "forlex-ai/unit")
            self.assertNotIn("private-response-marker", str(refused.exception))
            self.assertIn(("GET", "check-runs/3", None), calls)
            self.assertFalse(any(method == "PATCH" for method, _, _ in calls))

    def test_context_refuses_non_integer_created_check_identity(self):
        """Only an acknowledged positive integer id identifies a created original check."""
        for identity in (True, 3.0, "3", None, 0, -1):
            module = gate()
            event, responses, checks, calls = pr_api_fixture(module)
            api = module.github

            def invalid(repo, suffix, *, method="GET", body=None):
                result = api(repo, suffix, method=method, body=body)
                return {**result, "id": identity} if method == "POST" else result

            module.github = invalid
            with self.assertRaises(ValueError):
                module.context(event, "pull_request_target", "forlex-ai/unit")
            self.assertFalse(any(method == "PATCH" for method, _, _ in calls))

    def test_partial_publication_failure_downgrades_each_verified_original_check(self):
        """A failed or lost completion acknowledgement never leaves acknowledged success."""
        for failed_target in ("check-runs/3", "check-runs/4"):
            for lost_ack in (False, True):
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
                api = module.github

                def failing(repo, suffix, *, method="GET", body=None):
                    if (
                        method == "PATCH"
                        and suffix == failed_target
                        and body["conclusion"] == "success"
                    ):
                        if lost_ack:
                            api(repo, suffix, method=method, body=body)
                        else:
                            calls.append((method, suffix, body))
                        raise module.SecretScanRefusal("private-response-marker")
                    return api(repo, suffix, method=method, body=body)

                module.github = failing
                with self.assertRaises(ValueError) as refused:
                    module.publish(source, report)
                self.assertNotIn("private-response-marker", str(refused.exception))
                self.assertEqual(
                    [check.get("conclusion") for check in checks.values()], ["failure", "failure"]
                )
                for suffix in ("check-runs/3", "check-runs/4"):
                    writes = [
                        i
                        for i, (method, target, body) in enumerate(calls)
                        if method == "PATCH"
                        and target == suffix
                        and body["conclusion"] == "failure"
                    ]
                    self.assertEqual(len(writes), 1)
                    self.assertEqual(calls[writes[0] - 1], ("GET", suffix, None))

    def test_cleanup_continues_when_one_original_check_cannot_be_confirmed(self):
        """An outage, foreign identity or lost cleanup ack cannot skip the other owned target."""
        for failed_target in ("check-runs/3", "check-runs/4"):
            for fault in ("read", "write", "lost_ack", "unconfirmed", "foreign"):
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
                api = module.github
                cleaning = False

                def failing(repo, suffix, *, method="GET", body=None):
                    nonlocal cleaning
                    if (
                        method == "PATCH"
                        and suffix == "check-runs/4"
                        and body["conclusion"] == "success"
                    ):
                        calls.append((method, suffix, body))
                        cleaning = True
                        if fault == "foreign":
                            checks[failed_target]["app"]["id"] = 46505
                        raise module.SecretScanRefusal("private-response-marker")
                    if cleaning and suffix == failed_target:
                        if fault == "read" and method == "GET":
                            calls.append((method, suffix, body))
                            raise module.SecretScanRefusal("private-response-marker")
                        if method == "PATCH":
                            if fault == "write":
                                calls.append((method, suffix, body))
                                raise module.SecretScanRefusal("private-response-marker")
                            result = api(repo, suffix, method=method, body=body)
                            if fault == "lost_ack":
                                raise module.SecretScanRefusal("private-response-marker")
                            if fault == "unconfirmed":
                                return {**result, "status": "in_progress"}
                            return result
                    return api(repo, suffix, method=method, body=body)

                module.github = failing
                with self.assertRaises(ValueError) as refused:
                    module.publish(source, report)
                self.assertNotIn("private-response-marker", str(refused.exception))
                other = "check-runs/4" if failed_target == "check-runs/3" else "check-runs/3"
                self.assertEqual(checks[other].get("conclusion"), "failure")
                self.assertEqual(checks[other]["status"], "completed")
                self.assertIn(("GET", failed_target, None), calls)
                if fault == "foreign":
                    self.assertFalse(
                        any(
                            method == "PATCH"
                            and target == failed_target
                            and body["conclusion"] == "failure"
                            for method, target, body in calls
                        )
                    )

    def test_scanner_has_no_inherited_tokens_and_no_live_verification(self):
        """Verify scanner has no inherited tokens and no live verification."""
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
            scanner.write_text(
                "#!/usr/bin/env python3\nimport os,sys\nassert not any(k in os.environ for k in"
                " ('GH_TOKEN','GITHUB_TOKEN','AWS_SECRET_ACCESS_KEY'))\nassert '--no-verification'"
                " in sys.argv\nassert '--no-ignore-tag' in sys.argv\n"
            )
            scanner.chmod(0o700)
            original = os.environ.get("GH_TOKEN")
            os.environ["GH_TOKEN"] = "never-inherit-this-fixture"
            try:
                self.assertEqual(
                    gate().scan(repo, head, None, scanner, policy, "forlex-ai/unit", 10)["result"],
                    "pass",
                )
            finally:
                if original is None:
                    os.environ.pop("GH_TOKEN", None)
                else:
                    os.environ["GH_TOKEN"] = original

    def test_git_range_uses_merge_base_without_losing_intermediate_commits(self):
        """Verify git range uses merge base without losing intermediate commits."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)

            def commit(text):
                (repo / "file").write_text(text)
                subprocess.run(["git", "-C", str(repo), "add", "file"], check=True)
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
                        "change",
                    ],
                    check=True,
                )
                return subprocess.check_output(
                    ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
                ).strip()

            base = commit("safe")
            introduced = commit("synthetic secret introduced")
            head = commit("safe again")
            effective, commits = gate().git_range(repo, head, base)
            self.assertEqual(effective, base)
            self.assertIn(introduced, commits)
            self.assertIn(head, commits)

    def test_scan_timeout_fails_closed(self):
        """Verify scan timeout fails closed."""
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
            scanner.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(10)\n")
            scanner.chmod(0o700)
            self.assertEqual(
                gate().scan(repo, head, None, scanner, policy, "forlex-ai/unit", 0.1)["result"],
                "error",
            )

    def test_stale_pr_and_foreign_check_cannot_publish_success(self):
        """Refuse changed source and a check owned by another publishing app."""
        module = gate()
        source = {
            "repository": "forlex-ai/unit",
            "pr": 1,
            "head": "a" * 40,
            "base": "b" * 40,
            "check_id": 3,
        }
        report = {
            **source,
            "version": 1,
            "result": "pass",
            "blocked": 0,
            "suppressed": 0,
            "commit_count": 2,
        }
        calls = []

        def api(repository, suffix, *, method="GET", body=None):
            calls.append((method, suffix))
            if suffix.startswith("pulls/"):
                return {"state": "open", "head": {"sha": "c" * 40}, "base": {"sha": source["base"]}}
            return {
                "id": 3,
                "head_sha": source["head"],
                "name": "TruffleHog secret scan",
                "app": {"id": 46505},
            }

        module.github = api
        with self.assertRaises(ValueError):
            module.publish(source, report)
        self.assertFalse(any(method == "PATCH" for method, _ in calls))
        source["pr"] = None
        with self.assertRaises(ValueError):
            module.publish(source, report)
        self.assertFalse(any(method == "PATCH" for method, _ in calls))

    def test_original_check_identity_mismatch_never_patches(self):
        """Reject checks with a different original identity or publishing app."""
        source = {
            "repository": "forlex-ai/unit",
            "pr": 1,
            "head": "a" * 40,
            "base": "b" * 40,
            "check_id": 3,
        }
        report = {
            **source,
            "version": 1,
            "result": "pass",
            "blocked": 0,
            "suppressed": 0,
            "commit_count": 2,
        }
        owned = {
            "id": 3,
            "head_sha": source["head"],
            "name": "TruffleHog secret scan",
            "app": {"id": 15368},
        }
        for mismatched in (
            {**owned, "id": 4},
            {**owned, "head_sha": "c" * 40},
            {**owned, "name": "Other check"},
            {**owned, "app": {"id": 46505}},
        ):
            with self.subTest(mismatched=mismatched):
                module = gate()
                calls = []

                def api(
                    repository,
                    suffix,
                    *,
                    method="GET",
                    body=None,
                    calls=calls,
                    mismatched=mismatched,
                    module=module,
                ):
                    calls.append((method, suffix))
                    if suffix.startswith("pulls/"):
                        raise module.SecretScanRefusal("private current PR error")
                    return mismatched

                module.github = api
                with self.assertRaises(module.SecretScanRefusal):
                    module.publish(source, report)
                self.assertFalse(any(method == "PATCH" for method, _ in calls))
