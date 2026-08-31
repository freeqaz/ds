// The D84 fleet-scope secret-digest REGISTRATION surface (doc 16 §6.4/§9/§11.3) —
// the control-plane API + CLI half of the digest feed: it decides WHICH Vault
// trees the producer is allowed to read (the designation consent surface) and
// turns each designation / per-secret escape-hatch registration into a
// FLEET-scope digest registration that rides the EXISTING policy_log/PolicySink
// seam (D72) via identity/digest's PublishFleetPolicy/RevokeFleetPolicy.
//
// It introduces NO new proto and NO new RPC: registration is a policy artifact
// over the same orchestrator.v1.PolicyService append path the digest producer
// already drives (the §6.2 "two cadences, no third channel" rule). It depends on
// ../digest (the D39 producer + PolicySink seam) and ../kv-client (the D55
// OpenBao KV-v2 read-only client) ACROSS the module/seam boundary via the
// documented shapes — never editing their files.
//
// Identity touches plaintext only for DESIGNATED trees — the designated-prefix
// set IS the consent surface bounding the producer's read scope (D84, the D23 2c
// motion). DEFAULT: none until configured. Authority defaults (D84): org admin
// for org credentials, any developer for credentials they own.
//
// Deliberately OUTSIDE go.work — the same standalone-module pattern as ../mint,
// ../digest, and ../kv-client (a substrate swap must not perturb the workspace);
// GOWORK=off build legs. The only legal cross-tree import is proto/gen/go via
// replace (transitively, through ../digest). The AWS Secrets Manager second
// store and the dashboard are explicitly out of scope (slot behind the same seam
// later). Synthetic fixtures only (D50): no live Vault/KVM/metal anywhere.
module github.com/dream-serpent/dream-serpent/identity/fleetreg

go 1.25.11

require (
	github.com/dream-serpent/dream-serpent/identity/digest v0.0.0
	github.com/dream-serpent/dream-serpent/identity/kv-client v0.0.0-00010101000000-000000000000
	github.com/dream-serpent/dream-serpent/proto/gen/go v0.0.0
)

require google.golang.org/protobuf v1.36.11 // indirect

require (
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/grpc v1.81.1 // indirect
)

replace github.com/dream-serpent/dream-serpent/proto/gen/go => ../../proto/gen/go

replace github.com/dream-serpent/dream-serpent/identity/digest => ../digest

replace github.com/dream-serpent/dream-serpent/identity/kv-client => ../kv-client
