// SPDX-License-Identifier: Apache-2.0

// Package log1wire carries the per-commit D75 full-v6 round-trip assertion the
// doc 14 §2 LOG-1 checklist mandates: every address-bearing LOG-1 field is
// family-agnostic (`bytes` + AddressFamily, never fixed32), so a full 128-bit
// IPv6 literal must survive marshal → unmarshal byte-identically on every
// address field of every address-bearing message. Freezing the family-agnostic
// shape was time-locked (retrofitting v6 post-freeze is a breaking v2); this
// test is the executable form of that row, running per-commit from the freeze
// PR onward.
package log1wire

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// A full 16-byte IPv6 literal (2001:db8::8a2e:370:7334) and a second distinct
// one for dst/aimed-resolver fields, so a swap/truncation cannot cancel out.
var (
	v6A = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34}
	v6B = []byte{0xfd, 0x00, 0xab, 0xcd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
)

func session() *boundaryv1.SessionRef {
	return &boundaryv1.SessionRef{
		SessionUuid:      "00000000-0000-4000-8000-000000000001",
		HostId:           "host-a",
		HostSessionIndex: 16385, // > 2^14 so the mod-2^14 disambiguator is distinct
		TapName:          "dstap-16385",
	}
}

func roundTrip(t *testing.T, m proto.Message, out proto.Message) {
	t.Helper()
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := proto.Unmarshal(raw, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// TestFlowRecordV6RoundTrip asserts src/dst 16-byte addresses survive intact.
func TestFlowRecordV6RoundTrip(t *testing.T) {
	in := &boundaryv1.FlowRecord{
		Session:          session(),
		AddressFamily:    boundaryv1.AddressFamily_ADDRESS_FAMILY_IPV6,
		SrcAddr:          v6A,
		DstAddr:          v6B,
		SrcPort:          51515,
		DstPort:          443,
		IpProtocol:       6,
		CtMark:           0xD1004001,
		Leg:              boundaryv1.MarkLeg_MARK_LEG_AGENT_VM,
		MarkSessionIndex: 16385 % (1 << 14),
		RejectReason:     boundaryv1.RejectReason_REJECT_REASON_QUIC_BLOCKED,
	}
	out := &boundaryv1.FlowRecord{}
	roundTrip(t, in, out)
	if !bytes.Equal(out.GetSrcAddr(), v6A) || len(out.GetSrcAddr()) != 16 {
		t.Fatalf("src_addr v6 mangled: got %x", out.GetSrcAddr())
	}
	if !bytes.Equal(out.GetDstAddr(), v6B) || len(out.GetDstAddr()) != 16 {
		t.Fatalf("dst_addr v6 mangled: got %x", out.GetDstAddr())
	}
	if out.GetAddressFamily() != boundaryv1.AddressFamily_ADDRESS_FAMILY_IPV6 {
		t.Fatalf("address_family lost: %v", out.GetAddressFamily())
	}
}

// TestDnsEventV6RoundTrip asserts answer addresses and the D69 aimed_resolver
// addr:port pair carry full v6 literals intact.
func TestDnsEventV6RoundTrip(t *testing.T) {
	in := &boundaryv1.DnsEvent{
		Session:             session(),
		QueryFqdn:           "api.example.test",
		QueryType:           28, // AAAA
		AnswerFamily:        boundaryv1.AddressFamily_ADDRESS_FAMILY_IPV6,
		AnswerAddrs:         [][]byte{v6A, v6B},
		AaaaOnly:            true,
		AdmissionType:       boundaryv1.AdmissionType_ADMISSION_TYPE_NORMAL,
		Provenance:          &boundaryv1.Provenance{RuleId: "r1", PolicyLayer: "org", PolicyVersion: 7},
		AimedResolverFamily: boundaryv1.AddressFamily_ADDRESS_FAMILY_IPV6,
		AimedResolverAddr:   v6B,
		AimedResolverPort:   53,
	}
	out := &boundaryv1.DnsEvent{}
	roundTrip(t, in, out)
	if len(out.GetAnswerAddrs()) != 2 ||
		!bytes.Equal(out.GetAnswerAddrs()[0], v6A) ||
		!bytes.Equal(out.GetAnswerAddrs()[1], v6B) {
		t.Fatalf("answer_addrs v6 mangled: %x", out.GetAnswerAddrs())
	}
	if !bytes.Equal(out.GetAimedResolverAddr(), v6B) || len(out.GetAimedResolverAddr()) != 16 {
		t.Fatalf("aimed_resolver_addr v6 mangled: %x", out.GetAimedResolverAddr())
	}
	// Mandatory POL-3 provenance must survive (doc 14 §2: missing provenance
	// fails CI; this is the wire half of that row).
	if out.GetProvenance().GetPolicyVersion() != 7 {
		t.Fatalf("provenance lost: %v", out.GetProvenance())
	}
}
