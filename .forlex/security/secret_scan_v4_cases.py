"""Additional unchanged protocol cases; discovered through GateTests only."""

from secret_scan_cases import Path, gate, json, os, patch, pr_api_fixture, subprocess, tempfile


class _GateV4Cases:
    def test_branch_deletion_scans_retained_before_tip_instead_of_default_sha(self):
        """Deleted branches bind a full scan to the retained deleted tip, never the default head."""
        module = gate()
        event, _responses, checks, _calls = pr_api_fixture(module)
        event.update(ref="refs/heads/deleted", before="b" * 40, after="0" * 40, deleted=True)
        with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}):
            source = module.context(event, "push", "forlex-ai/unit")
        self.assertEqual((source["head"], source["base"]), ("b" * 40, None))
        self.assertEqual([check["head_sha"] for check in checks.values()], ["b" * 40])
        self.assertEqual([check["name"] for check in checks.values()], ["TruffleHog history scan"])

    def test_branch_deletion_without_a_valid_retained_tip_creates_no_check(self):
        """Missing, zero and malformed deleted tips refuse before any default-head check exists."""
        for before in (None, "0" * 40, "B" * 40, "b" * 39):
            with self.subTest(before=before):
                module = gate()
                event, _responses, _checks, calls = pr_api_fixture(module)
                event.update(ref="refs/heads/deleted", after="0" * 40, deleted=True)
                if before is not None:
                    event["before"] = before
                with (
                    patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}),
                    self.assertRaises(ValueError),
                ):
                    module.context(event, "push", "forlex-ai/unit")
                self.assertFalse(any(method == "POST" for method, _, _ in calls))

    def test_head_changing_during_merge_polling_refuses_the_stale_event(self):
        """A ready prospective merge for a newer head cannot reuse an older PR event."""
        module = gate()
        event, _responses, _checks, calls = pr_api_fixture(module)
        api = module.github
        reads = 0

        def moving(repo, suffix, *, method="GET", body=None):
            nonlocal reads
            result = api(repo, suffix, method=method, body=body)
            if suffix == "pulls/1":
                reads += 1
                if reads == 1:
                    return {**result, "mergeable": None, "merge_commit_sha": None}
                return {**result, "head": {"sha": "e" * 40}}
            if suffix == "git/commits/" + "c" * 40:
                return {**result, "parents": [{"sha": "b" * 40}, {"sha": "e" * 40}]}
            return result

        module.github = moving
        with patch.object(module.time, "sleep"), self.assertRaises(ValueError):
            module.context(event, "pull_request_target", "forlex-ai/unit")
        self.assertGreater(reads, 1)
        self.assertFalse(any(method == "POST" for method, _, _ in calls))

    def test_history_checks_have_a_distinct_fixed_name_from_pr_admission(self):
        """A push or complete-history success cannot satisfy the fixed PR gate name."""
        for kind, number in (
            ("push", 0),
            ("schedule", 0),
            ("workflow_dispatch", 0),
            ("workflow_dispatch", 1),
            ("pull_request_target", 0),
        ):
            with self.subTest(kind=kind, number=number):
                module = gate()
                event, _responses, checks, calls = pr_api_fixture(module)
                event["before"] = "b" * 40
                with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}):
                    source = module.context(event, kind, "forlex-ai/unit", number)
                expected = "TruffleHog secret scan" if source["pr"] else "TruffleHog history scan"
                self.assertEqual({check["name"] for check in checks.values()}, {expected})
                report = {
                    **source,
                    "version": 1,
                    "result": "pass",
                    "blocked": 0,
                    "suppressed": 0,
                    "commit_count": 3,
                }
                if source["pr"]:
                    report.update(
                        candidate_policy_validated=True,
                        candidate_policy_source=source["merge"],
                        candidate_policy_blob="f" * 40,
                    )
                self.assertEqual(module.publish(source, report)["conclusion"], "success")
                self.assertEqual(
                    {body["output"]["title"] for method, _, body in calls if method == "PATCH"},
                    {expected},
                )

    def test_missing_old_push_tip_scans_all_reachable_new_history_but_pr_is_strict(self):
        """An orphaned force-push source is complete without the old tip; PR scope remains exact."""
        module = gate()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            for message in ("first", "second"):
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
            head = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            expected = subprocess.check_output(
                ["git", "-C", str(repo), "rev-list", "HEAD"], text=True
            ).splitlines()
            self.assertEqual(
                module.git_range(repo, head, "f" * 40, full_if_nonforward=True), (None, expected)
            )
            with self.assertRaises(ValueError):
                module.git_range(repo, head, "f" * 40)
            with self.assertRaises(ValueError):
                module.git_range(repo, "e" * 40, "f" * 40, full_if_nonforward=True)

    def test_pending_mergeability_is_polled_before_creating_either_check(self):
        """GitHub's asynchronous null mergeability is retried using authenticated current facts."""
        module = gate()
        event, _responses, checks, _calls = pr_api_fixture(module)
        api = module.github
        reads = 0

        def pending(repo, suffix, *, method="GET", body=None):
            nonlocal reads
            result = api(repo, suffix, method=method, body=body)
            if method == "GET" and suffix == "pulls/1":
                reads += 1
                if reads < 3:
                    return {**result, "mergeable": None, "merge_commit_sha": None}
            if method == "POST":
                self.assertGreaterEqual(reads, 3)
            return result

        module.github = pending
        with patch.object(module.time, "sleep"):
            source = module.context(event, "pull_request_target", "forlex-ai/unit")
        self.assertEqual(reads, 3)
        self.assertEqual(
            (source["head"], source["base"], source["merge"]), ("a" * 40, "b" * 40, "c" * 40)
        )
        self.assertEqual(len(checks), 2)

    def test_polling_waits_for_exact_current_prospective_merge_parents(self):
        """A stale merge object cannot authorize checks even after mergeability becomes true."""
        module = gate()
        event, _responses, checks, _calls = pr_api_fixture(module)
        api = module.github
        reads = 0

        def stale_merge(repo, suffix, *, method="GET", body=None):
            nonlocal reads
            result = api(repo, suffix, method=method, body=body)
            if suffix == "git/commits/" + "c" * 40:
                reads += 1
                if reads < 2:
                    return {**result, "parents": [{"sha": "d" * 40}, {"sha": "a" * 40}]}
            if method == "POST":
                self.assertGreaterEqual(reads, 2)
            return result

        module.github = stale_merge
        with patch.object(module.time, "sleep"):
            source = module.context(event, "pull_request_target", "forlex-ai/unit")
        self.assertEqual(source["base"], "b" * 40)
        self.assertEqual(reads, 2)
        self.assertEqual(len(checks), 2)

    def test_publication_and_cleanup_reject_checks_from_the_other_scan_mode(self):
        """Name separation remains exact during preflight, terminal writes and cleanup."""
        for kind in ("push", "pull_request_target"):
            with self.subTest(kind=kind):
                module = gate()
                event, _responses, checks, calls = pr_api_fixture(module)
                event["before"] = "b" * 40
                with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}):
                    source = module.context(event, kind, "forlex-ai/unit")
                wrong = "TruffleHog secret scan" if kind == "push" else "TruffleHog history scan"
                for check in checks.values():
                    check["name"] = wrong
                with self.assertRaises(ValueError):
                    module.publish(source, {"result": "error"})
                self.assertFalse(any(method == "PATCH" for method, _, _ in calls))

    def test_publication_preflight_failure_cleans_independently_verified_checks(self):
        """Initial identity outages and mismatches must not strand the other original check."""
        for failed_target in ("check-runs/3", "check-runs/4"):
            for fault in ("once", "outage", "foreign"):
                with self.subTest(target=failed_target, fault=fault):
                    module = gate()
                    event, _responses, checks, calls = pr_api_fixture(module)
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
                    failed = False
                    if fault == "foreign":
                        checks[failed_target]["app"]["id"] = 46505

                    def failing(
                        repo,
                        suffix,
                        *,
                        method="GET",
                        body=None,
                        failed_target=failed_target,
                        fault=fault,
                        api=api,
                        calls=calls,
                        module=module,
                    ):
                        nonlocal failed
                        if (
                            method == "GET"
                            and suffix == failed_target
                            and fault != "foreign"
                            and (not failed or fault == "outage")
                        ):
                            failed = True
                            calls.append((method, suffix, body))
                            raise module.SecretScanRefusal("private-preflight-response-marker")
                        return api(repo, suffix, method=method, body=body)

                    module.github = failing
                    with self.assertRaises(ValueError) as refused:
                        module.publish(source, report)
                    self.assertNotIn("private-preflight-response-marker", str(refused.exception))
                    other = "check-runs/4" if failed_target == "check-runs/3" else "check-runs/3"
                    self.assertEqual(checks[other]["status"], "completed")
                    self.assertEqual(checks[other]["conclusion"], "failure")
                    patches = [
                        (suffix, body) for method, suffix, body in calls if method == "PATCH"
                    ]
                    self.assertTrue(all(body["conclusion"] == "failure" for _, body in patches))
                    if fault == "once":
                        self.assertEqual(checks[failed_target]["conclusion"], "failure")
                    else:
                        self.assertFalse(any(suffix == failed_target for suffix, _ in patches))
                    for index, (method, suffix, _) in enumerate(calls):
                        if method == "PATCH":
                            self.assertEqual(calls[index - 1], ("GET", suffix, None))

    def test_unready_or_conflicting_merge_polling_is_bounded_and_creates_no_checks(self):
        """Pending, conflicting and malformed readiness cannot become premature admission."""
        for readiness in (None, False, "true", 1):
            with self.subTest(readiness=readiness):
                module = gate()
                event, responses, _checks, calls = pr_api_fixture(module)
                responses["pulls/1"]["mergeable"] = readiness
                with patch.object(module.time, "sleep"), self.assertRaises(ValueError):
                    module.context(event, "pull_request_target", "forlex-ai/unit")
                reads = sum(method == "GET" and suffix == "pulls/1" for method, suffix, _ in calls)
                self.assertGreaterEqual(reads, 1)
                self.assertLessEqual(reads, 5)
                if readiness is None:
                    self.assertGreater(reads, 1)
                self.assertFalse(any(method == "POST" for method, _, _ in calls))


class _NativeV4Cases:
    def test_native_missing_old_push_tip_still_detects_reachable_canary(self):
        """Real offline detection covers new reachable history when the orphaned old tip is absent."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            value = self.canary()
            (repo / "fixture.txt").write_text("token=" + value + "\n")
            introduced = self.commit(repo)
            (repo / "fixture.txt").unlink()
            head = self.commit(repo)
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            module = gate()
            report = module.scan(
                repo,
                head,
                "f" * 40,
                Path(os.environ["TRUFFLEHOG_BINARY"]),
                policy,
                "forlex-ai/unit",
                60,
                full_if_nonforward=True,
            )
            self.assertEqual(report["result"], "fail", json.dumps(report))
            self.assertIsNone(report["effective_base"])
            self.assertEqual(report["commit_count"], 2)
            self.assertGreater(report["blocked"], 0)
            self.assertTrue(any(row["commit"] == introduced for row in report["findings"]))
            self.assertNotIn(value, json.dumps(report))
            self.assertEqual(
                module.scan(
                    repo,
                    head,
                    "f" * 40,
                    Path(os.environ["TRUFFLEHOG_BINARY"]),
                    policy,
                    "forlex-ai/unit",
                    60,
                )["result"],
                "error",
            )
