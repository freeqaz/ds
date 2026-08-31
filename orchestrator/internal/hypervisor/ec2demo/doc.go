// Package ec2demo is the EC2 demo driver: the same hypervisor.v1 contract
// implemented over the AWS API (D31/D32/D35) for per-demo footprints
// (infra/terraform/aws-demo/). It exists to be the contract's FIRST
// CAPABILITY-FLAG HONESTY TEST (doc 15 §5.1, TODOs).
//
// Honest capability flags (D35, Nomad-style):
//
//	supports_migrate           = false
//	supports_instant_clone     = false  (AMI/instance launch behind CloneFromImage)
//	supports_disk_delta_export = false
//
// Suspend/Resume map to instance stop/start — best-effort, with NO
// transparency claim. A driver that lies in its flags is a contract bug;
// the conformance suite drives wire behavior against these flags.
//
// D30 anti-pattern note applies here exactly as in the sibling libvirt
// package: this is a sibling driver behind the proto contract, not a
// plugin under a generic multi-hypervisor layer — none is to be built.
//
// D33 scope note: the cloud-SDK ban is a DATA-PLANE constraint (the OSS
// data plane installs on vanilla Linux metal). This demo driver is
// control-plane tooling for D32 demos; it still enters only behind the
// public hypervisor.v1 contract, so removing it removes nothing else.
//
// Governing decisions: D32, D35, D30, D33. Primary doc:
// docs/15-orchestrator-design.md §5.1.
package ec2demo
