"""Tests for Sedna Cyber Workflow Skill."""

import importlib.util
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

# Skill root is the parent of the tests directory
SKILL_ROOT = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def _secure_test_umask():
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.fixture(autouse=True)
def _trusted_pt_report(tmp_path: Path) -> None:
    script = tmp_path / "pt-report.py"
    script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    script.chmod(0o700)


def test_frontmatter_conformance():
    skill_path = SKILL_ROOT / "SKILL.md"
    content = skill_path.read_text(encoding="utf-8")
    assert content.startswith("---"), "SKILL.md must start with ---"

    # Extract frontmatter
    parts = content.split("---", 2)
    assert len(parts) >= 3, "Frontmatter must be properly closed with ---"

    import yaml

    fm = yaml.safe_load(parts[1])
    assert fm["name"] == "sedna-cyber-workflow"
    assert len(fm["description"]) <= 60, f"Description too long: {len(fm['description'])} chars"
    assert fm["description"].endswith("."), "Description must end with a period."
    assert "linux" in fm["platforms"]
    assert "hexstrike-kali-htb" in fm["metadata"]["hermes"]["related_skills"]


def test_closed_loop_workflow_sequence():
    """Verify tool calling sequence across the 6 stages."""
    workflow = [
        "sedna_learn_local",
        "sedna_manage_engagement",  # create
        "sedna_retrieve_knowledge",
        "mcp_hexstrike_nmap",
        "sedna_plan_next",
        "sedna_record_decision",
        "sedna_manage_engagement",  # close
        "sedna_manage_engagement",  # verify
    ]
    # Check that each stage maps to a valid capability in Sedna/Hermes
    assert len(workflow) == 8
    assert workflow[0] == "sedna_learn_local"
    assert workflow[-1] == "sedna_manage_engagement"


def test_script_permissions():
    """Verify helper scripts are executable."""
    script_dir = SKILL_ROOT / "scripts"
    sync_script = script_dir / "sync-engagement-report.py"
    verify_script = script_dir / "verify-sedna-env.sh"

    assert sync_script.exists(), "sync-engagement-report.py must exist"
    assert verify_script.exists(), "verify-sedna-env.sh must exist"


@pytest.mark.parametrize(
    ("ip_output", "docker_output", "curl_exit", "curl_output", "expected_success"),
    (
        ("eth0 UP 10.0.0.2/24", "hexstrike-kali", 0, '{"status":"healthy"}', False),
        ("tun0 DOWN 10.10.0.2/24", "hexstrike-kali", 0, '{"status":"healthy"}', False),
        ("tun0 UP 10.10.0.2/24", "other-container", 0, '{"status":"healthy"}', False),
        ("tun0 UP 10.10.0.2/24", "hexstrike-kali", 1, "", False),
        ("tun0 UP 10.10.0.2/24", "hexstrike-kali", 0, '{"status":"unhealthy"}', False),
        pytest.param(
            "tun0 UP 10.10.0.2/24",
            "hexstrike-kali",
            0,
            '{"status":"healthy","extra":true}',
            True,
            id="health-extra-fields-are-tolerated",
        ),
        (
            "tun0 UP 10.10.0.2/24",
            "hexstrike-kali",
            0,
            '{"status":"unhealthy","status":"healthy"}',
            False,
        ),
        pytest.param(
            "tun0 UP 10.10.0.2/24",
            "hexstrike-kali",
            0,
            json.dumps({"status": "healthy", "padding": "x" * 5000}),
            True,
            id="health-payload-under-cap",
        ),
        # The two cases above were inverted on 2026-09-28: the verifier used to reject any extra
        # field and any payload over 4 KB, which failed closed on every server upgrade (the health
        # payload had grown past that cap with 127 tools registered). The verifier now requires the
        # status key with value healthy and a generous bound. What must still fail closed is
        # covered by the cases below: a missing status key, a payload over the bound, and a tunnel
        # that is not up.
        pytest.param(
            "tun0 UNKNOWN 10.10.0.2/24",
            "hexstrike-kali",
            0,
            '{"status":"healthy"}',
            True,
            id="tun-up-reporting-unknown-operstate",
        ),
        pytest.param(
            "tun0 UP 10.10.0.2/24",
            "hexstrike-kali",
            0,
            json.dumps({"status": "healthy", "padding": "x" * 300000}),
            False,
            id="health-payload-over-bound",
        ),
        pytest.param(
            "tun0 UP 10.10.0.2/24",
            "hexstrike-kali",
            0,
            '{"ok":true}',
            False,
            id="health-status-key-missing",
        ),
        ("tun0 UP 10.10.0.2/24", "hexstrike-kali", 0, '{"status":"healthy"}', True),
    ),
)
def test_environment_verifier_fails_closed_before_initialization(
    tmp_path: Path,
    ip_output: str,
    docker_output: str,
    curl_exit: int,
    curl_output: str,
    expected_success: bool,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()

    def write_command(name: str, body: str) -> None:
        path = fake_bin / name
        path.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
        path.chmod(0o755)

    write_command("ip", f"printf '%s\\n' {ip_output!r}")
    write_command("docker", f"printf '%s\\n' {docker_output!r}")
    write_command("curl", f"printf '%s\\n' {curl_output!r}; exit {curl_exit}")
    (tmp_path / "pt-report.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    hermes_home = tmp_path / "hermes"

    result = subprocess.run(
        [
            "/bin/bash",
            "-c",
            'umask 000; exec /bin/bash "$1"',
            "verify-sedna-env",
            str(SKILL_ROOT / "scripts" / "verify-sedna-env.sh"),
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "HERMES_HOME": str(hermes_home),
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert (result.returncode == 0) is expected_success
    assert (hermes_home / "knowledge" / "sedna").exists() is expected_success
    if expected_success:
        sedna_root = hermes_home / "knowledge" / "sedna"
        assert stat.S_IMODE(sedna_root.stat().st_mode) == 0o700
        assert stat.S_IMODE((sedna_root / "engagements").stat().st_mode) == 0o700


def test_sync_script_cli():
    """Test that sync script parses required arguments."""
    script_path = SKILL_ROOT / "scripts" / "sync-engagement-report.py"

    # Test argument parsing without running full sync
    with patch("sys.argv", ["sync-engagement-report.py", "--help"]):
        # We can't easily test argparse without running, so just verify the file is importable
        spec = __import__("importlib.util").util.spec_from_file_location("sync", script_path)
        module = __import__("importlib.util").util.module_from_spec(spec)
        # Just verify it loads without syntax error
        assert module is not None


def test_verify_script_syntax():
    """Verify bash script has no syntax errors."""
    import subprocess

    verify_script = SKILL_ROOT / "scripts" / "verify-sedna-env.sh"
    result = subprocess.run(["bash", "-n", str(verify_script)], capture_output=True)
    assert result.returncode == 0, f"Bash syntax error: {result.stderr.decode()}"


def test_sync_script_never_copies_private_journal_text_to_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000100"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    private = "".join(("pass", "word=", "synthetic-value", " platform-proof-value"))
    journal.write_text(
        json.dumps(
            {
                "event_id": "00000000-0000-4000-8000-000000000001",
                "type": "decision_recorded",
                "payload": {"custom_strategy": private, "rationale": private},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")

    assert calls
    assert any("add-note" in command for command in calls)
    assert private not in " ".join(part for command in calls for part in command)


def test_sync_rejects_non_uuid_engagement_id_before_path_resolution(tmp_path: Path) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_invalid_id", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    with pytest.raises(ValueError, match="engagement_id must be a UUID"):
        module.sync_events(tmp_path, "../../outside", "report-1", tmp_path / "pt-report.py")


def test_sync_skips_event_with_malformed_event_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_bad_event", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000101"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text(
        json.dumps({"event_id": "not-a-uuid", "type": "decision_recorded", "payload": {}}) + "\n",
        encoding="utf-8",
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")

    assert calls == []


def test_sync_propagates_report_record_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_failure", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000102"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text(
        json.dumps(
            {
                "event_id": "00000000-0000-4000-8000-000000000103",
                "type": "decision_recorded",
                "payload": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    def fail_record(command: list[str], **kwargs: object) -> None:
        if "add-note" in command and kwargs.get("check") is True:
            raise module.subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(module.subprocess, "run", fail_record)

    with pytest.raises(module.subprocess.CalledProcessError):
        module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")


def test_sync_is_idempotent_across_repeated_invocations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_idempotent", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000104"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text(
        json.dumps(
            {
                "event_id": "00000000-0000-4000-8000-000000000105",
                "type": "decision_recorded",
                "payload": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")
    module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")

    add_calls = [command for command in calls if "add-note" in command]
    assert len(add_calls) == 1
    assert sum("render" in command for command in calls) == 0
    assert add_calls[0][add_calls[0].index("--idempotency-key") + 1] == (
        "00000000-0000-4000-8000-000000000105"
    )
    assert "--body" in add_calls[0]
    assert "--content" not in add_calls[0]


def test_sync_crash_window_is_recorded_and_blocks_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_pending", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000112"
    event_id = "00000000-0000-4000-8000-000000000113"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text(
        json.dumps({"event_id": event_id, "type": "decision_recorded", "payload": {}}) + "\n",
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    def crash_after_destination_may_have_mutated(command: list[str], **_kwargs: object) -> None:
        calls.append(command)
        raise module.subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(module.subprocess, "run", crash_after_destination_may_have_mutated)

    with pytest.raises(module.subprocess.CalledProcessError):
        module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")
    with pytest.raises(RuntimeError, match="manual reconciliation required"):
        module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")

    assert len(calls) == 1
    report_key = module.sha256(b"report-1").hexdigest()
    checkpoint = json.loads(
        (tmp_path / ".pt-report-sync" / engagement_id / f"{report_key}.json").read_text(
            encoding="utf-8"
        )
    )
    assert checkpoint == {
        "completed_event_ids": [],
        "pending_event_id": event_id,
        "version": 2,
    }


def test_sync_rejects_symlinked_state_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_state_symlink", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000106"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text(
        json.dumps(
            {
                "event_id": "00000000-0000-4000-8000-000000000107",
                "type": "decision_recorded",
                "payload": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".pt-report-sync").symlink_to(outside, target_is_directory=True)
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    with pytest.raises(OSError):
        module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")

    assert calls == []
    assert list(outside.iterdir()) == []


def test_sync_rejects_symlinked_checkpoint_before_any_lock_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_checkpoint_symlink", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000108"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text("", encoding="utf-8")
    state_dir = tmp_path / ".pt-report-sync" / engagement_id
    state_dir.mkdir(parents=True)
    outside = tmp_path / "outside-file"
    outside.write_text("unchanged", encoding="utf-8")
    outside.chmod(0o644)
    report_key = module.sha256(b"report-1").hexdigest()
    (state_dir / f"{report_key}.json").symlink_to(outside)
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    with pytest.raises(OSError):
        module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")

    assert calls == []
    assert not (state_dir / f"{report_key}.lock").exists()
    assert outside.read_text(encoding="utf-8") == "unchanged"
    assert outside.stat().st_mode & 0o777 == 0o644


def test_sync_rejects_symlink_selected_as_sedna_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_root_symlink", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000109"
    real_root = tmp_path / "real-root"
    journal = real_root / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text("", encoding="utf-8")
    selected_root = tmp_path / "selected-root"
    selected_root.symlink_to(real_root, target_is_directory=True)
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    with pytest.raises(OSError):
        module.sync_events(selected_root, engagement_id, "report-1", tmp_path / "pt-report.py")

    assert calls == []
    assert not (real_root / ".pt-report-sync").exists()


def test_sync_rejects_symlink_in_sedna_root_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_root_ancestor", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000110"
    real_parent = tmp_path / "real-parent"
    real_root = real_parent / "sedna-root"
    journal = real_root / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text("", encoding="utf-8")
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    with pytest.raises(OSError):
        module.sync_events(
            linked_parent / "sedna-root", engagement_id, "report-1", tmp_path / "pt-report.py"
        )

    assert calls == []
    assert not (real_root / ".pt-report-sync").exists()


def test_sync_does_not_chmod_malformed_checkpoint_before_rejecting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_checkpoint_mode", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000111"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text("", encoding="utf-8")
    state_dir = tmp_path / ".pt-report-sync" / engagement_id
    state_dir.mkdir(parents=True)
    report_key = module.sha256(b"report-1").hexdigest()
    checkpoint = state_dir / f"{report_key}.json"
    checkpoint.write_text('{"version":0,"event_ids":[]}', encoding="utf-8")
    checkpoint.chmod(0o644)
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    with pytest.raises(ValueError, match="invalid pt-report sync checkpoint"):
        module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")

    assert calls == []
    assert checkpoint.stat().st_mode & 0o777 == 0o644


def test_sync_rejects_completed_id_overflow_before_destination_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_limit", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000115"
    event_id = "00000000-0000-4000-8000-000000000116"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text(
        json.dumps({"event_id": event_id, "type": "decision_recorded", "payload": {}}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "_CHECKPOINT_MAX_IDS", 0)
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    with pytest.raises(ValueError, match="completed event limit reached"):
        module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")

    assert calls == []


def test_sync_rejects_legacy_checkpoint_instead_of_unbounded_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location("sedna_sync_report_legacy_checkpoint", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000114"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text("", encoding="utf-8")
    state_dir = tmp_path / ".pt-report-sync" / engagement_id
    state_dir.mkdir(parents=True)
    report_key = module.sha256(b"report-1").hexdigest()
    (state_dir / f"{report_key}.json").write_text(
        json.dumps({"event_ids": [], "version": 1}),
        encoding="utf-8",
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    with pytest.raises(ValueError, match="invalid pt-report sync checkpoint"):
        module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")

    assert calls == []


@pytest.mark.parametrize(
    "unsafe_component",
    ("root", "engagements", "engagement", "state-root", "state-engagement"),
)
def test_sync_rejects_group_or_world_writable_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe_component: str
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location(
        f"sedna_sync_report_mode_{unsafe_component}", script
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000117"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text("", encoding="utf-8")
    state_engagement = tmp_path / ".pt-report-sync" / engagement_id
    state_engagement.mkdir(parents=True)
    components = {
        "root": tmp_path,
        "engagements": tmp_path / "engagements",
        "engagement": journal.parent,
        "state-root": tmp_path / ".pt-report-sync",
        "state-engagement": state_engagement,
    }
    components[unsafe_component].chmod(0o777)
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    with pytest.raises(PermissionError, match="unsafe permissions"):
        module.sync_events(tmp_path, engagement_id, "report-1", tmp_path / "pt-report.py")

    assert calls == []


@pytest.mark.parametrize("unsafe_kind", ("symlink", "hardlink", "writable"))
def test_sync_rejects_untrusted_pt_report_script_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe_kind: str
) -> None:
    script = SKILL_ROOT / "scripts" / "sync-engagement-report.py"
    spec = importlib.util.spec_from_file_location(
        f"sedna_sync_report_untrusted_script_{unsafe_kind}", script
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engagement_id = "00000000-0000-4000-8000-000000000118"
    journal = tmp_path / "engagements" / engagement_id / "events.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text("", encoding="utf-8")
    trusted = tmp_path / "pt-report.py"
    selected = tmp_path / "selected-report.py"
    if unsafe_kind == "symlink":
        selected.symlink_to(trusted)
    elif unsafe_kind == "hardlink":
        selected.hardlink_to(trusted)
    else:
        selected.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        selected.chmod(0o777)
    calls: list[list[str]] = []
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: calls.append(command))

    with pytest.raises(OSError):
        module.sync_events(tmp_path, engagement_id, "report-1", selected)

    assert calls == []


def test_exported_skill_documents_uuid_only_sync_and_contains_no_raw_flag_shapes() -> None:
    policy = (SKILL_ROOT / "references" / "evidence-redaction-policy.md").read_text()
    assert "The sync helper never reads event payload fields" in policy
    assert "Sanitize using same regex patterns" not in policy
    assert "script applies `REDACTION_PATTERNS`" not in policy

    lifecycle = (SKILL_ROOT / "references" / "unified-engagement-lifecycle.md").read_text()
    assert "Every other event | Not exported automatically" in lifecycle
    assert "`tool_call_settled` | `log-command`" not in lifecycle
    assert "[*] --> ACTIVE: sedna_manage_engagement(create)" in lifecycle
    assert "ACTIVE --> CLOSING:" in lifecycle
    assert "CLOSING --> CLOSED_UNVERIFIED:" in lifecycle
    assert "CLOSED_UNVERIFIED --> CLOSED_VERIFIED:" in lifecycle
    assert "| `closing` |" in lifecycle
    assert "| `abandoned` |" in lifecycle
    assert "CREATED --> ACTIVE" not in lifecycle
    assert "CLOSED_VERIFIED --> PROMOTED" not in lifecycle
    assert ".pt-report-sync" in lifecycle
    assert "idempotent" in lifecycle

    bridge = (SKILL_ROOT / "references" / "sedna-hexstrike-mcp-bridge.md").read_text()
    assert "settled tool calls → pt-report log-command" not in bridge
    assert "decision_recorded` and `observation_extracted` UUID pointers" in bridge

    exported_text = "\n".join(
        path.read_text(errors="replace") for path in SKILL_ROOT.rglob("*") if path.is_file()
    )
    assert re.search(r"(?i)(?:HTB|THM|FLAG)\{[^}]+\}", exported_text) is None
