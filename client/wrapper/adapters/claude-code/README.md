# adapters/claude-code/ — THE runtime-specific code

**Owner:** Attach & client · **OSS** (D15/D25) · **Decisions:** D20, D38, D49

This directory is **the only runtime-specific code in the repository**
(D20/D38). It parses Claude Code's subagent protocol and translates it into
`dreamserpent.attach.v1` events. Everything outside this directory — wrapper
core, TUI, orchestrator, entrypoint — must stay runtime-ignorant; if you find
a CC-ism leaking out of here, that is a bug against D38.

**Version pin (D49):** the Claude Code version this adapter parses is pinned
in the golden image (`images/golden/`), so unreviewed protocol drift cannot
reach production. Drift is detected on schedule, not in incidents: the
nightly canary in `../../goldentrace/` runs against CC-latest, and refreshing
the pin means an insta-style cassette diff review, then bumping the image pin
and this adapter together.

**Adding a runtime = adding a sibling adapter** (OpenClaw, our own agent
loop — Claude Code is "the first of N", D38). Do not branch inside this
adapter on runtime identity; create `adapters/<runtime>/` next door. The
golden-trace harness investment carries over to a new runtime; these
fixtures need not (D49 rationale).
