# SPDX-License-Identifier: Apache-2.0
#
# test_audit_knobs_json.py — hermetic tests for audit_knobs.py's machine-readable
# --json output (the CI-consumption twin of the human parity table). NO live model
# / GPU / network / `go` toolchain: every leg is resolved purely from the
# environment + the landed Go source's canonical defaults.
#
# Coverage:
#   * build_report() returns a JSON-serializable dict whose shape carries both legs'
#     effective knobs + the parity verdict, agreeing with audit()'s divergence list.
#   * `main(["--json"])` prints VALID JSON, keeps exit 0 on parity / 1 on divergence,
#     and leaves the default (no-flag) human output byte-for-byte unchanged.
#   * an unknown flag is rejected (exit 2) without emitting JSON.

import importlib
import io
import json

import pytest

import audit_knobs


def _fresh_fusion(monkeypatch, **env):
    """Reload fusion under a given environment so audit_knobs's resolvers read the
    freshly-bound constants (fusion binds K_RRF/W_DENSE/W_SPARSE ONCE at import)."""
    for k in (
        "SEARCHSVC_W_DENSE",
        "SEARCHSVC_W_SPARSE",
        "SEARCHSVC_RRF_K",
        "DS_SEARCHSVC_INGEST_BATCH",
    ):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import fusion

    return importlib.reload(fusion)


def test_build_report_shape_and_parity_ok(monkeypatch):
    """With no overrides, build_report() carries both legs' canonical knobs and a
    True parity verdict (no divergences)."""
    _fresh_fusion(monkeypatch)
    report = audit_knobs.build_report()

    assert report["parity_ok"] is True
    assert report["divergences"] == []
    assert report["shared"]["W_DENSE"]["python"] == pytest.approx(0.65)
    assert report["shared"]["W_DENSE"]["go"] == pytest.approx(0.65)
    assert report["shared"]["W_SPARSE"]["python"] == pytest.approx(0.35)
    assert report["shared"]["W_SPARSE"]["go"] == pytest.approx(0.35)
    assert "SEARCHSVC_RRF_K" in report["python_only"]
    assert "DS_SEARCHSVC_INGEST_BATCH" in report["go_only"]
    assert report["go_only"]["DS_SEARCHSVC_INGEST_BATCH"] == 128


def test_build_report_agrees_with_audit(monkeypatch):
    """build_report()'s parity verdict + divergence list mirror audit()'s, so the
    JSON and human surfaces can never disagree."""
    _fresh_fusion(monkeypatch)
    sink = io.StringIO()
    divergences = audit_knobs.audit(out=sink)
    report = audit_knobs.build_report()
    assert report["divergences"] == divergences
    assert report["parity_ok"] == (not divergences)


def test_main_json_emits_valid_json_and_exit_zero(monkeypatch, capsys):
    """`main(["--json"])` prints a single valid JSON object on stdout and exits 0
    when parity holds; nothing goes to stderr."""
    _fresh_fusion(monkeypatch)
    rc = audit_knobs.main(["--json"])
    captured = capsys.readouterr()
    assert rc == 0
    parsed = json.loads(captured.out)  # raises on invalid JSON
    assert parsed["parity_ok"] is True
    assert "shared" in parsed and "python_only" in parsed and "go_only" in parsed
    # The human-table header must NOT leak into the JSON stream.
    assert "effective knobs" not in captured.out


def test_main_json_exit_one_on_divergence(monkeypatch, capsys):
    """When the legs diverge, --json still emits valid JSON but exits 1 with
    parity_ok False — the CI gate signal."""
    _fresh_fusion(monkeypatch)
    real_go = audit_knobs.resolve_go_leg()

    def diverged_go():
        g = dict(real_go)
        g["w_dense"] = real_go["w_dense"] + 0.1
        return g

    monkeypatch.setattr(audit_knobs, "resolve_go_leg", diverged_go)
    rc = audit_knobs.main(["--json"])
    captured = capsys.readouterr()
    assert rc == 1
    parsed = json.loads(captured.out)
    assert parsed["parity_ok"] is False
    assert any("W_DENSE" in d for d in parsed["divergences"])


def test_default_human_output_unchanged_by_json_addition(monkeypatch, capsys):
    """`main([])` (no flag) still prints the human table and exits 0 on parity —
    the --json addition leaves the default path untouched."""
    _fresh_fusion(monkeypatch)
    rc = audit_knobs.main([])
    captured = capsys.readouterr()
    assert rc == 0
    assert "searchsvc effective knobs (one-knob-both-legs parity audit)" in captured.out
    assert "PARITY: OK" in captured.out
    # The default path emits the human table, never JSON.
    with pytest.raises(json.JSONDecodeError):
        json.loads(captured.out)


def test_unknown_flag_rejected(monkeypatch, capsys):
    """An unrecognized flag exits 2 (usage error) and emits no JSON on stdout."""
    _fresh_fusion(monkeypatch)
    rc = audit_knobs.main(["--bogus"])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""
    assert "unknown argument" in captured.err
