"""Additional complete v5 cases, discovered through the standalone owner entrypoint."""

import tarfile
import zipfile

from secret_scan_cases import (
    Path,
    exception,
    finding,
    gate,
    json,
    lifecycle_rows,
    os,
    patch,
    proof_url,
    subprocess,
    tempfile,
    time,
)


class _GateV5Cases:
    def test_archive_prefixes_and_original_signature_free_names_are_refused(self):
        """Known, truncated and ambiguous archive headers cannot enter native admission."""
        module = gate()
        signatures = (
            b"PK\x03\x04",
            b"PK\x05\x06",
            b"PK\x07\x08",
            b"7z\xbc\xaf\x27\x1c",
            b"Rar!\x1a\x07\x00",
            b"Rar!\x1a\x07\x01\x00",
            b"\x1f\x8b",
            b"BZh",
            b"\xfd7zXZ\x00",
            b"\x04\x22\x4d\x18",
            b"\x02\x21\x4c\x18",
            b"LZIP",
            b"\x28\xb5\x2f\xfd",
            b"\x50\x2a\x4d\x18",
            b"\x5f\x2a\x4d\x18",
            b"\xff\x06\x00\x00sNaPpY",
            b"\xff\x06\x00\x00S2sTwO",
            b"!<arch>\n",
            b"\xed\xab\xee\xdb",
            b"070701",
            b"070702",
            b"070707",
            b"\x71\xc7",
            b"\xc7\x71",
            b"\x1f\x9d",
            b"MSCF",
            b"xar!",
            b"\x78\x9c",
            b"\x08\x1d",
        )
        source = [{"file": "ordinary.txt"}]
        for prefix in signatures:
            with self.subTest(signature=prefix.hex()):
                self.assertTrue(module.unsupported_archive(prefix, source))
                self.assertTrue(module.unsupported_archive(prefix + b"not a valid archive", source))
        header = tarfile.TarInfo("fixture").tobuf(format=tarfile.USTAR_FORMAT)
        self.assertTrue(module.unsupported_archive(header[:512], source))
        malformed = bytearray(512)
        malformed[257:262] = b"ustar"
        self.assertTrue(module.unsupported_archive(bytes(malformed), source))
        legacy = tarfile.TarInfo("fixture").tobuf(format=tarfile.GNU_FORMAT)
        legacy = bytearray(legacy[:512])
        legacy[257:512] = bytes(255)
        legacy[148:156] = b"        "
        legacy[148:156] = f"{sum(legacy):06o}\0 ".encode()
        self.assertTrue(module.unsupported_archive(bytes(legacy), source))
        for name in (
            "fixture.br",
            "fixture.BR",
            "fixture.tar",
            "fixture.sz",
            "fixture.s2",
            "fixture.zip",
        ):
            self.assertTrue(module.unsupported_archive(b"plain or malformed", [{"file": name}]))
            self.assertTrue(module.unsupported_archive(b"", [{"file": name}]))
        self.assertTrue(
            module.unsupported_archive(b"plain", [{"file": "first.txt"}, {"file": "second.br"}])
        )
        for prefix in (b"", b"plain text", b"token=fixture", b"\x78\x00", b"\x50\x2a\x4d\x19"):
            self.assertFalse(module.unsupported_archive(prefix, source))
        self.assertFalse(module.unsupported_archive(b"text mentions PK\x03\x04 later", source))
        self.assertFalse(module.unsupported_archive(b"plain", [{"file": "branch.py"}]))

    def test_archive_refusal_prevents_scanner_execution_and_redacts_names(self):
        """Materialization refuses every original association before any native grant."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in (
                ("sensitive-archive.txt", b"PK\x03\x04"),
                ("sensitive-format.br", b"plain"),
            ):
                with self.subTest(kind=Path(name).suffix):
                    repo = root / name
                    repo.mkdir()
                    subprocess.run(["git", "init", "-q", str(repo)], check=True)
                    (repo / name).write_bytes(content)
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
                            "fixture",
                        ],
                        check=True,
                    )
                    head = subprocess.check_output(
                        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
                    ).strip()
                    policy = root / "policy.json"
                    policy.write_text('{"version":1,"exceptions":[]}')
                    module = gate()
                    with patch.object(module, "run_bounded_scanner") as scanner:
                        report = module.scan(
                            repo, head, None, root / "scanner", policy, "forlex-ai/unit", 60
                        )
                    self.assertEqual(report["result"], "error")
                    scanner.assert_not_called()
                    self.assertNotIn("sensitive", json.dumps(report))
                    (repo / name).unlink()

    def test_lifecycle_pair_is_mandatory_ordered_and_unique_per_invocation(self):
        """Controlled missing/partial/reversed/duplicate traces cannot grant a nonempty scan."""
        running, finished = lifecycle_rows()
        invalid = (
            [],
            [running],
            [finished],
            [finished, running],
            [running, running, finished],
            [running, finished, finished],
            [running, finished, running, finished],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "fixture.txt").write_text("ordinary nonempty source\n")
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
                    "fixture",
                ],
                check=True,
            )
            head = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            scanner = root / "scanner"
            diagnostics = root / "stderr"
            for rows in (*invalid, [running, finished]):
                with self.subTest(messages=[row["msg"] for row in rows]):
                    stream = "".join(json.dumps(row) + "\n" for row in rows)
                    diagnostics.write_text(stream)
                    scanner.write_text(
                        "#!/usr/bin/env python3\nimport sys\nsys.stderr.write("
                        + repr(stream)
                        + ")\n"
                    )
                    scanner.chmod(0o700)
                    report = gate().scan(repo, head, None, scanner, policy, "forlex-ai/unit", 10)
                    if rows == [running, finished]:
                        gate().validate_diagnostics(diagnostics)
                        self.assertEqual(report["result"], "pass", json.dumps(report))
                        self.assertEqual(report["payload_count"], 3)
                    else:
                        with self.assertRaises(ValueError):
                            gate().validate_diagnostics(diagnostics)
                        self.assertEqual(report["result"], "error", json.dumps(report))
                        self.assertNotIn("source_manager_worker_id", json.dumps(report))

    def test_only_exact_native_lifecycle_diagnostics_are_accepted(self):
        """A log level alone cannot prove complete detection or hide skipped content."""
        running, finished = lifecycle_rows()
        invalid = [
            {"level": "info", "msg": "sensitive skipped archive"},
            {"level": "info-2", "msg": "skipping large archive file"},
            {"level": "debug", "msg": "sensitive incomplete detection"},
            {**running, "error": "sensitive error"},
            {**finished, "error": None},
            {**running, "with_units": False},
            {**running, "source_manager_worker_id": "敏感123"},
            {**running, "source_manager_worker_id": "A12345"},
            {**running, "logger": "unknown"},
            {**running, "level": "info-1"},
            {**running, "ts": "2026-10-13"},
            {**running, "ts": "2026-02-30T00:00:00Z"},
            {**finished, "trufflehog_version": "3.99.3"},
            {**finished, "chunks": True},
            {**finished, "bytes": -1},
            {**finished, "scan_duration": "NaNms"},
            {**finished, "scan_duration": "-1s"},
            {**finished, "scan_duration": "1e3s"},
            {**finished, "verification_caching": {"Hits": 0}},
            {
                **finished,
                "verification_caching": {**finished["verification_caching"], "Hits": False},
            },
        ]
        invalid.extend(
            {k: v for k, v in row.items() if k != key} for row in (running, finished) for key in row
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stderr"
            path.write_text("".join(json.dumps(row) + "\n" for row in (running, finished)))
            gate().validate_diagnostics(path)
            for row in invalid:
                with self.subTest(keys=sorted(row)):
                    rows = (
                        [running, row] if row.get("msg") == "finished scanning" else [row, finished]
                    )
                    path.write_text("".join(json.dumps(item) + "\n" for item in rows))
                    with self.assertRaises(ValueError) as refused:
                        gate().validate_diagnostics(path)
                    self.assertNotIn("sensitive", str(refused.exception))

    def test_raw_finding_counts_must_match_each_completion_metric(self):
        """Valid JSON row loss and mismatched verification classes cannot grant success."""
        cases = (
            ([], (0, 1), "error"),
            ([], (1, 0), "error"),
            ([False], (0, 2), "error"),
            ([True], (2, 0), "error"),
            ([False], (1, 0), "error"),
            ([True], (0, 1), "error"),
            ([False, True], (1, 0), "error"),
            ([False, False], (0, 1), "error"),
            ([], (0, 0), "pass"),
            ([False], (0, 1), "fail"),
            ([True], (1, 0), "fail"),
            ([False, True], (1, 1), "fail"),
            ([0], (0, 1), "error"),
            ([1], (1, 0), "error"),
            (["false"], (0, 1), "error"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            body = b"ordinary nonempty content\n"
            (repo / "fixture.txt").write_bytes(body)
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
                    "fixture",
                ],
                check=True,
            )
            head = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            marker = "sensitive-lost-result"
            cases = [(*case, False) for case in cases] + [([False], (0, 2), "error", True)]
            for states, metrics, expected, suppress in cases:
                with self.subTest(states=states, metrics=metrics):
                    module = gate()

                    def captured(
                        command,
                        _environment,
                        output,
                        errors,
                        _deadline,
                        states=states,
                        metrics=metrics,
                    ):
                        payload = next(
                            p for p in Path(command[-1]).iterdir() if p.read_bytes() == body
                        )
                        rows = [
                            {
                                **finding(marker, verified=state),
                                "SourceMetadata": {
                                    "Data": {"Filesystem": {"file": str(payload), "line": 1}}
                                },
                            }
                            for state in states
                        ]
                        output.write_text("".join(json.dumps(row) + "\n" for row in rows))
                        running, finished = lifecycle_rows()
                        finished.update(verified_secrets=metrics[0], unverified_secrets=metrics[1])
                        errors.write_text(json.dumps(running) + "\n" + json.dumps(finished) + "\n")
                        return 0

                    rule = {**exception(finding(marker, path="fixture.txt")), "commit": head}
                    rule["proof"] = proof_url(rule)
                    policy.write_text(
                        json.dumps({"version": 1, "exceptions": [rule] if suppress else []})
                    )
                    with patch.object(module, "run_bounded_scanner", captured):
                        report = module.scan(
                            repo, head, None, root / "scanner", policy, "forlex-ai/unit", 10
                        )
                    self.assertEqual(report["result"], expected, json.dumps(report))
                    self.assertNotIn(marker, json.dumps(report))
                    if expected == "error":
                        self.assertNotIn("blocked", report)


class _NativeV5Cases:
    def test_native_json_stdout_write_failure_cannot_receive_pass(self):
        """Actual pinned /dev/full ENOSPC produces a nonzero metric but no JSON rows."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            raw = self.canary()
            (repo / "fixture.txt").write_text("token=" + raw + "\n")
            head = self.commit(repo)
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            module = gate()
            captured = {}

            def failed_sink(command, environment, output, errors, deadline):
                with Path("/dev/full").open("wb") as sink, errors.open("wb") as diagnostics:
                    result = subprocess.run(
                        command,
                        stdout=sink,
                        stderr=diagnostics,
                        env=environment,
                        timeout=max(0.01, deadline - time.monotonic()),
                        check=False,
                    )
                output.write_bytes(b"")
                captured["exit"] = result.returncode
                captured["rows"] = [json.loads(line) for line in errors.read_text().splitlines()]
                return result.returncode

            with patch.object(module, "run_bounded_scanner", failed_sink):
                report = module.scan(
                    repo,
                    head,
                    None,
                    Path(os.environ["TRUFFLEHOG_BINARY"]),
                    policy,
                    "forlex-ai/unit",
                    60,
                )
            self.assertEqual(captured["exit"], 0)
            self.assertEqual(
                [row["msg"] for row in captured["rows"]], ["running source", "finished scanning"]
            )
            self.assertEqual(captured["rows"][-1]["verified_secrets"], 0)
            self.assertEqual(captured["rows"][-1]["unverified_secrets"], 1)
            self.assertEqual(report["result"], "error", json.dumps(report))
            self.assertNotIn(raw, json.dumps(report))

    def test_native_plain_canary_still_blocks_after_archive_preflight(self):
        """Refusing archive gaps preserves ordinary real offline detection."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            raw = self.canary()
            (repo / "fixture.txt").write_text("token=" + raw + "\n")
            report = self.scan(root, repo, self.commit(repo))
            self.assertEqual(report["result"], "fail", json.dumps(report))
            self.assertGreater(report["blocked"], 0)
            self.assertNotIn(raw, json.dumps(report))

    def test_native_valid_oversize_zip_canary_cannot_receive_pass(self):
        """A real >2GiB member with a small compressed Git blob cannot hide a canary."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            raw = self.canary()
            source = repo / "fixture.data"
            with (
                zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive,
                archive.open("fixture.txt", "w", force_zip64=True) as stream,
            ):
                stream.write(("token=" + raw + "\n").encode())
                chunk = b"0" * (32 * 1024 * 1024)
                for _ in range(64):
                    stream.write(chunk)
            with zipfile.ZipFile(source) as archive:
                self.assertGreater(archive.getinfo("fixture.txt").file_size, 2 << 30)
            self.assertLess(source.stat().st_size, 4 * 1024 * 1024)
            report = self.scan(root, repo, self.commit(repo))
            self.assertEqual(report["result"], "error", json.dumps(report))
            self.assertNotIn(raw, json.dumps(report))

    def test_native_zip_ignored_svg_canary_cannot_receive_pass(self):
        """A real ZIP ignored-extension member is refused before native's silent skip."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            raw = self.canary()
            with zipfile.ZipFile(repo / "fixture.data", "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("fixture.svg", "token=" + raw + "\n")
            report = self.scan(root, repo, self.commit(repo))
            self.assertEqual(report["result"], "error", json.dumps(report))
            self.assertNotIn(raw, json.dumps(report))
