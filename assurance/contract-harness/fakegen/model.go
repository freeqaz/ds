// SPDX-License-Identifier: Apache-2.0

// Package fakegen is the fake-generation step of the proto codegen pipeline
// (doc 06 §2.1, doc 15 §5.6). Given a proto package's COMPILED gRPC contract —
// its grpc.ServiceDesc and the protobuf service descriptor reachable from it —
// it derives a ServiceModel and emits a programmable in-memory fake server plus
// a fake-client helper. "Programmable" means canned responses plus recorded
// calls (doc 06 §2.1), never null stubs: each method has a settable responder
// and every call is captured for later assertion.
//
// Why drive off the compiled contract rather than re-parse .proto: the
// grpc.ServiceDesc + protoreflect.ServiceDescriptor ARE the frozen contract's
// machine form (the same artifact buf emits and `buf breaking` gates). Reading
// them keeps the fake bound to exactly what the stubs expose — a fake can never
// drift from a method the stubs don't have, and a new RPC at a re-freeze shows
// up here automatically. The pipeline thus needs no separate protoc plugin to
// stay in lockstep with the Go target; it consumes that target's output.
//
// The generator is deterministic: identical input contract -> byte-identical
// output, so the emitted fakes commit cleanly under proto/gen/go and a
// regeneration in CI is a no-op diff (the codegen-drift discipline,
// proto/FREEZE.md / .github/workflows/contracts.yml).
package fakegen

import (
	"fmt"
	"sort"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// StreamKind classifies an RPC's framing, which decides the shape of the fake's
// method handler and recorder.
type StreamKind int

const (
	// Unary: one request in, one response out.
	Unary StreamKind = iota
	// ClientStream: a stream of requests in, one response out (e.g. the host
	// agent's ReportHeartbeat, doc 15 §5.2).
	ClientStream
	// ServerStream: one request in, a stream of responses out (e.g.
	// WatchSession, doc 15 §5.3).
	ServerStream
	// BidiStream: streams in both directions.
	BidiStream
)

func (k StreamKind) String() string {
	switch k {
	case Unary:
		return "unary"
	case ClientStream:
		return "client-stream"
	case ServerStream:
		return "server-stream"
	case BidiStream:
		return "bidi-stream"
	default:
		return "unknown"
	}
}

// Method is one RPC in the contract, with the Go-level type information the
// emitter needs to write a typed, compiling fake.
type Method struct {
	Name string     // RPC name, e.g. "ReportHeartbeat"
	Kind StreamKind // framing

	// InputGoType / OutputGoType are the unqualified generated Go type names for
	// the request / response messages, e.g. "ReportHeartbeatRequest". They live
	// in the same generated package as the stubs (GoPackage), so the emitted
	// fake — which sits in a sibling sub-package — refers to them qualified.
	InputGoType  string
	OutputGoType string
}

// ServiceModel is the derived, emitter-ready view of one service contract.
type ServiceModel struct {
	// ServiceName is the fully-qualified proto service name, e.g.
	// "dreamserpent.hostagent.v1.HostAgentService".
	ServiceName string

	// GoServiceName is the generated Go service identifier, e.g.
	// "HostAgentService" (the prefix of HostAgentServiceServer etc.).
	GoServiceName string

	// StubImportPath is the import path of the generated stub package the fake
	// builds against, e.g.
	// ".../proto/gen/go/dreamserpent/hostagent/v1".
	StubImportPath string

	// StubPackageName is that package's Go name, e.g. "hostagentv1".
	StubPackageName string

	// FakePackageName is the emitted fake package's Go name, e.g.
	// "hostagentv1fake".
	FakePackageName string

	Methods []Method
}

// NeedsIO reports whether any method reads the client stream in a Recv loop —
// i.e. a client-stream or bidi RPC, the only arms that reference io.EOF. The
// emitter uses it to gate the "io" import, so a service with only unary and
// server-stream methods compiles without an unused-import error.
func (m *ServiceModel) NeedsIO() bool {
	for _, meth := range m.Methods {
		if meth.Kind == ClientStream || meth.Kind == BidiStream {
			return true
		}
	}
	return false
}

// Input describes one service contract to generate a fake for. The caller passes
// the compiled grpc.ServiceDesc (which the stub package exports as e.g.
// HostAgentService_ServiceDesc) plus the Go package coordinates the emitted fake
// must reference. ServiceDesc carries the method/stream framing and the
// fully-qualified service name; the protobuf service descriptor (resolved from
// the global registry by that name) carries the request/response message types.
type Input struct {
	ServiceDesc *grpc.ServiceDesc

	// StubImportPath / StubPackageName / GoServiceName locate the generated stub
	// package and service the fake binds to.
	StubImportPath  string
	StubPackageName string
	GoServiceName   string
}

// BuildModel derives a ServiceModel from a compiled service contract. It is the
// bridge from "what the stubs compiled to" to "what the emitter writes": the RPC
// set and framing come from the grpc.ServiceDesc; the request/response Go type
// names come from the protobuf service descriptor resolved out of the global
// registry (every frozen proto file registers itself there at init). Returning
// an error rather than guessing keeps a fake from ever claiming a method or
// message the contract does not actually expose.
func BuildModel(in Input) (*ServiceModel, error) {
	if in.ServiceDesc == nil {
		return nil, fmt.Errorf("fakegen: nil ServiceDesc")
	}
	if in.GoServiceName == "" {
		return nil, fmt.Errorf("fakegen: empty GoServiceName for %s", in.ServiceDesc.ServiceName)
	}
	sd, err := lookupServiceDescriptor(in.ServiceDesc.ServiceName)
	if err != nil {
		return nil, err
	}

	model := &ServiceModel{
		ServiceName:     in.ServiceDesc.ServiceName,
		GoServiceName:   in.GoServiceName,
		StubImportPath:  in.StubImportPath,
		StubPackageName: in.StubPackageName,
		FakePackageName: in.StubPackageName + "fake",
	}

	methods := sd.Methods()
	for i := 0; i < methods.Len(); i++ {
		md := methods.Get(i)
		inGo, err := goTypeName(md.Input())
		if err != nil {
			return nil, fmt.Errorf("fakegen: %s.%s input: %w", in.ServiceDesc.ServiceName, md.Name(), err)
		}
		outGo, err := goTypeName(md.Output())
		if err != nil {
			return nil, fmt.Errorf("fakegen: %s.%s output: %w", in.ServiceDesc.ServiceName, md.Name(), err)
		}
		model.Methods = append(model.Methods, Method{
			Name:         string(md.Name()),
			Kind:         streamKind(md),
			InputGoType:  inGo,
			OutputGoType: outGo,
		})
	}

	// Deterministic output: emit methods in proto-declaration order, which the
	// descriptor already preserves, but sort defensively so a registry quirk can
	// never reorder a committed fake (codegen-drift discipline).
	sort.SliceStable(model.Methods, func(i, j int) bool {
		return model.Methods[i].Name < model.Methods[j].Name
	})
	return model, nil
}

func streamKind(md protoreflect.MethodDescriptor) StreamKind {
	switch {
	case md.IsStreamingClient() && md.IsStreamingServer():
		return BidiStream
	case md.IsStreamingClient():
		return ClientStream
	case md.IsStreamingServer():
		return ServerStream
	default:
		return Unary
	}
}

func lookupServiceDescriptor(fqName string) (protoreflect.ServiceDescriptor, error) {
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(fqName))
	if err != nil {
		return nil, fmt.Errorf("fakegen: service %q not in the global proto registry "+
			"(is the stub package imported?): %w", fqName, err)
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("fakegen: %q resolved to a %T, not a service", fqName, d)
	}
	return sd, nil
}

// goTypeName maps a message descriptor to its generated Go type's unqualified
// name. It resolves the concrete message type from the global type registry and
// reads the Go struct name off the reflected value, so the emitter writes the
// exact identifier protoc-gen-go produced — no name-mangling guesswork.
func goTypeName(md protoreflect.MessageDescriptor) (string, error) {
	mt, err := protoregistry.GlobalTypes.FindMessageByName(md.FullName())
	if err != nil {
		return "", fmt.Errorf("message %q not registered: %w", md.FullName(), err)
	}
	// The generated Go type's local name equals the proto message name for the
	// messages on these seams (protoc-gen-go's default mapping); confirm via the
	// reflected descriptor so a future nested/renamed message is caught loudly
	// rather than mis-emitted.
	name := string(mt.Descriptor().Name())
	if name == "" {
		return "", fmt.Errorf("message %q has empty Go name", md.FullName())
	}
	return name, nil
}
