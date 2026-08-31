module github.com/dream-serpent/dream-serpent/assurance/guardrail-conformance

go 1.25.11

// Standard library only. This package states and asserts the doc 06 §3c /
// doc 16 §13 guardrail-conformance claims against synthetic fixtures (D50); it
// drives no real services (that is conformance-adapter/'s job — README.md), so
// it has zero dependencies and no cross-tree imports. The module is deliberately
// NOT in the repo go.work `use` list: it is run standalone (GOWORK=off) like the
// identity/* modules, keeping the claims package independent of production build
// state.
