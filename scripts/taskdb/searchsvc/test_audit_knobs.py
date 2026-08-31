# SPDX-License-Identifier: Apache-2.0
#
# test_audit_knobs.py — hermetic tests for the "one knob, both legs" parity audit
# (audit_knobs.py). NO live model / GPU / network / `go` toolchain: every leg is
# resolved purely from the environment + the landed Go source's canonical defaults.
#
# Coverage:
#   * default (no override) -> both legs resolve the canonical W_ knobs -> parity OK.
#   * a shared env override (SEARCHSVC_W_DENSE) -> reflected in BOTH legs -> parity OK.
#   * a SIMULATED divergence (the Go default monkeypatched away from the Python
#     binding) -> flagged, audit() returns a divergence, main() exits non-zero.
#   * the Python leg is read from the fusion module's BOUND constants (verbatim),
#     and the Go-only / Python-only knobs surface on the right leg.

import importlib
import io
import os

import pytest

import audit_knobs


def _fresh_fusion(monkeypatch, **env):
    """Reload fusion under a given environment so audit_knobs.resolve_python_leg
    reads the freshly-bound constants (fusion binds K_RRF/W_DENSE/W_SPARSE ONCE at
    import). Returns the reloaded module."""
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


def test_defaults_parity_ok(monkeypatch):
    """With no overrides, both legs resolve the canonical 0.65 / 0.35 and the audit
    reports parity OK (no divergences, exit 0)."""
    _fresh_fusion(monkeypatch)  # canonical bind
    out = io.StringIO()
    divergences = audit_knobs.audit(out=out)
    assert divergences == []
    text = out.getvalue()
    assert "PARITY: OK" in text
    assert audit_knobs.main([]) == 0


def test_shared_override_reflected_in_both_legs(monkeypatch):
    """A shared SEARCHSVC_W_DENSE override moves BOTH legs to the same value, so the
    audit still reports parity OK — the whole point of the single knob."""
    _fresh_fusion(monkeypatch, SEARCHSVC_W_DENSE="0.8", SEARCHSVC_W_SPARSE="0.2")

    py = audit_knobs.resolve_python_leg()
    go = audit_knobs.resolve_go_leg()
    assert py["w_dense"] == pytest.approx(0.8)
    assert go["w_dense"] == pytest.approx(0.8)
    assert py["w_sparse"] == pytest.approx(0.2)
    assert go["w_sparse"] == pytest.approx(0.2)

    out = io.StringIO()
    divergences = audit_knobs.audit(out=out)
    assert divergences == []
    assert "PARITY: OK" in out.getvalue()
    assert audit_knobs.main([]) == 0


def test_simulated_divergence_is_flagged(monkeypatch):
    """If the Go leg resolved a DIFFERENT W_DENSE than the Python leg (a name/default
    drift), the audit flags it, audit() returns a divergence, and main() exits 1.

    We simulate by monkeypatching resolve_go_leg to return a mismatched W_DENSE while
    the Python leg keeps its canonical binding — the exact failure the verifier must
    catch."""
    _fresh_fusion(monkeypatch)  # python leg = canonical 0.65

    real_go = audit_knobs.resolve_go_leg()

    def diverged_go():
        g = dict(real_go)
        g["w_dense"] = real_go["w_dense"] + 0.1  # drifted Go default
        return g

    monkeypatch.setattr(audit_knobs, "resolve_go_leg", diverged_go)

    out = io.StringIO()
    divergences = audit_knobs.audit(out=out)
    assert len(divergences) == 1
    assert "W_DENSE" in divergences[0]
    text = out.getvalue()
    assert "PARITY: FAIL" in text
    assert "DIVERGENT" in text
    assert audit_knobs.main([]) == 1


def test_python_leg_reads_fusion_bound_constants(monkeypatch):
    """resolve_python_leg reports the fusion module's ACTUAL bound constants
    (verbatim), including the fusion-only SEARCHSVC_RRF_K override."""
    fusion = _fresh_fusion(monkeypatch, SEARCHSVC_RRF_K="42", SEARCHSVC_W_DENSE="0.7")
    py = audit_knobs.resolve_python_leg()
    assert py["rrf_k"] == fusion.K_RRF == 42
    assert py["w_dense"] == fusion.W_DENSE == pytest.approx(0.7)


def test_rrf_k_is_python_only_and_batch_is_go_only(monkeypatch):
    """SEARCHSVC_RRF_K surfaces on the Python leg only; DS_SEARCHSVC_INGEST_BATCH on
    the Go leg only (and the Go env override is honored)."""
    _fresh_fusion(monkeypatch, SEARCHSVC_RRF_K="33", DS_SEARCHSVC_INGEST_BATCH="256")

    py = audit_knobs.resolve_python_leg()
    go = audit_knobs.resolve_go_leg()

    assert "rrf_k" in py and "rrf_k" not in go
    assert "ingest_batch" in go and "ingest_batch" not in py
    assert py["rrf_k"] == 33
    assert go["ingest_batch"] == 256

    out = io.StringIO()
    audit_knobs.audit(out=out)
    text = out.getvalue()
    assert "SEARCHSVC_RRF_K" in text
    assert "DS_SEARCHSVC_INGEST_BATCH" in text


def test_go_invalid_batch_falls_back_to_default(monkeypatch):
    """A present-but-invalid DS_SEARCHSVC_INGEST_BATCH loud-falls back to the Go
    canonical default (mirrors resolveIngestBatchSize), never crashing the audit."""
    _fresh_fusion(monkeypatch, DS_SEARCHSVC_INGEST_BATCH="not-an-int")
    go = audit_knobs.resolve_go_leg()
    # The Go default parsed from searchsvc_ingest.go (defaultIngestBatchSize=128).
    assert go["ingest_batch"] == 128


def test_go_negative_batch_clamped_to_default(monkeypatch):
    """A sub-1 batch override is clamped to the Go default (mirrors the n<1 branch)."""
    _fresh_fusion(monkeypatch, DS_SEARCHSVC_INGEST_BATCH="0")
    go = audit_knobs.resolve_go_leg()
    assert go["ingest_batch"] == 128


def test_go_defaults_track_landed_source(monkeypatch):
    """The Go-leg defaults are PARSED from the landed Go source (not hardcoded), so
    they equal the documented canonical values when no env override is present."""
    _fresh_fusion(monkeypatch)
    go = audit_knobs.resolve_go_leg()
    assert go["w_dense"] == pytest.approx(0.65)
    assert go["w_sparse"] == pytest.approx(0.35)
    assert go["ingest_batch"] == 128


def test_go_source_unreadable_uses_fallback(monkeypatch, tmp_path):
    """If the Go source can't be read, the audit loud-falls back to the documented
    canonical defaults rather than crashing (stripped-checkout resilience)."""
    monkeypatch.setattr(audit_knobs, "_GO_EMBEDDINGS", str(tmp_path / "missing.go"))
    monkeypatch.setattr(audit_knobs, "_GO_INGEST", str(tmp_path / "missing.go"))
    _fresh_fusion(monkeypatch)
    go = audit_knobs.resolve_go_leg()
    assert go["w_dense"] == pytest.approx(audit_knobs._FALLBACK_W_DENSE)
    assert go["w_sparse"] == pytest.approx(audit_knobs._FALLBACK_W_SPARSE)
    assert go["ingest_batch"] == audit_knobs._FALLBACK_INGEST_BATCH
