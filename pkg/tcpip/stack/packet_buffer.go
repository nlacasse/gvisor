// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at //
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// A PacketBuffer contains all the data of a network packet.
//
// As a PacketBuffer traverses up the stack, it may be necessary to pass it to
// multiple endpoints. Clone() should be called in such cases so that
// modifications to the Data field do not affect other copies.
type PacketBuffer struct {
	_ noCopy

	// PacketBufferEntry is used to build an intrusive list of
	// PacketBuffers.
	PacketBufferEntry

	// Data holds the payload of the packet. For inbound packets, it also
	// holds the headers, which are consumed as the packet moves up the
	// stack. Headers are guaranteed not to be split across views.
	//
	// The bytes backing Data are immutable, but Data itself may be trimmed
	// or otherwise modified.
	Data buffer.VectorisedView

	// Header holds the headers of outbound packets. As a packet is passed
	// down the stack, each layer adds to Header. Note that forwarded
	// packets don't populate Headers on their way out -- their headers and
	// payload are never parsed out and remain in Data.
	//
	// TODO(gvisor.dev/issue/170): Forwarded packets don't currently
	// populate Header, but should. This will be doable once early parsing
	// (https://github.com/google/gvisor/pull/1995) is supported.
	Header buffer.Prependable

	// These fields are used by both inbound and outbound packets. They
	// typically overlap with the Data and Header fields.
	//
	// The bytes backing these views are immutable. Each field may be nil
	// if either it has not been set yet or no such header exists (e.g.
	// packets sent via loopback may not have a link header).
	//
	// These fields may be Views into other slices (either Data or Header).
	// SR dosen't support this, so deep copies are necessary in some cases.
	LinkHeader      buffer.View
	NetworkHeader   buffer.View
	TransportHeader buffer.View

	// Hash is the transport layer hash of this packet. A value of zero
	// indicates no valid hash has been set.
	Hash uint32

	// Owner is implemented by task to get the uid and gid.
	// Only set for locally generated packets.
	Owner tcpip.PacketOwner

	// The following fields are only set by the qdisc layer when the packet
	// is added to a queue.
	EgressRoute           *Route
	GSOOptions            *GSO
	NetworkProtocolNumber tcpip.NetworkProtocolNumber

	// NatDone indicates if the packet has been manipulated as per NAT
	// iptables rule.
	NatDone bool
}

// Clone makes a copy of pk. It clones the Data field, which creates a new
// VectorisedView but does not deep copy the underlying bytes.
//
// Clone also does not deep copy any of its other fields.
//
// FIXME(b/153685824): Data gets copied but not other header references.
func (pk *PacketBuffer) Clone() *PacketBuffer {
	return &PacketBuffer{
		PacketBufferEntry:     pk.PacketBufferEntry,
		Data:                  pk.Data.Clone(nil),
		Header:                pk.Header,
		LinkHeader:            pk.LinkHeader,
		NetworkHeader:         pk.NetworkHeader,
		TransportHeader:       pk.TransportHeader,
		Hash:                  pk.Hash,
		Owner:                 pk.Owner,
		EgressRoute:           pk.EgressRoute,
		GSOOptions:            pk.GSOOptions,
		NetworkProtocolNumber: pk.NetworkProtocolNumber,
		NatDone:               pk.NatDone,
	}
}

// Describe returns the packet in human-readable form. It looks for headers in
// the *Header fields, so unparsed incoming packets may show little data.
//
// Describe is intended primarily for debugging.
func (pk PacketBuffer) Describe(protocol tcpip.NetworkProtocolNumber) string {
	// TODO(gvisor.dev/issue/170): Have PacketBuffer know its own network protocol.
	// Figure out the network layer info.
	var transProto uint8
	src := tcpip.Address("unknown")
	dst := tcpip.Address("unknown")
	id := 0
	size := uint16(0)
	var fragmentOffset uint16
	var moreFragments bool

	switch protocol {
	case header.IPv4ProtocolNumber:
		if len(pk.NetworkHeader) < header.IPv4MinimumSize {
			return fmt.Sprintf("[IPv4 protocol number, but packet is too small]")
		}
		ipv4 := header.IPv4(pk.NetworkHeader)
		fragmentOffset = ipv4.FragmentOffset()
		moreFragments = ipv4.Flags()&header.IPv4FlagMoreFragments == header.IPv4FlagMoreFragments
		src = ipv4.SourceAddress()
		dst = ipv4.DestinationAddress()
		transProto = ipv4.Protocol()
		size = ipv4.TotalLength() - uint16(ipv4.HeaderLength())
		id = int(ipv4.ID())

	case header.IPv6ProtocolNumber:
		if len(pk.NetworkHeader) < header.IPv6MinimumSize {
			return fmt.Sprintf("[IPv6 protocol number, but packet is too small]")
		}
		ipv6 := header.IPv6(pk.NetworkHeader)
		src = ipv6.SourceAddress()
		dst = ipv6.DestinationAddress()
		transProto = ipv6.NextHeader()
		size = ipv6.PayloadLength()

	case header.ARPProtocolNumber:
		if len(pk.NetworkHeader) < header.ARPSize {
			return fmt.Sprintf("[ARP protocol number, but packet is too small]")
		}
		arp := header.ARP(pk.NetworkHeader)
		return fmt.Sprintf(
			"arp %v (%v) -> %v (%v) valid:%v",
			tcpip.Address(arp.ProtocolAddressSender()), tcpip.LinkAddress(arp.HardwareAddressSender()),
			tcpip.Address(arp.ProtocolAddressTarget()), tcpip.LinkAddress(arp.HardwareAddressTarget()),
			arp.IsValid(),
		)
	default:
		return fmt.Sprintf("unknown network protocol")
	}

	// Figure out the transport layer info.
	transName := "unknown"
	srcPort := uint16(0)
	dstPort := uint16(0)
	details := ""
	switch tcpip.TransportProtocolNumber(transProto) {
	case header.ICMPv4ProtocolNumber:
		// TODO(gvisor.dev/issue/170): ICMP packets aren't early-parsed
		// yet.
		return fmt.Sprintf("icmpv4")

	case header.ICMPv6ProtocolNumber:
		// TODO(gvisor.dev/issue/170): ICMP packets aren't early-parsed
		// yet.
		return fmt.Sprintf("icmpv6")

	case header.UDPProtocolNumber:
		transName = "udp"
		if len(pk.TransportHeader) < header.UDPMinimumSize {
			return fmt.Sprintf("%v -> %v transport protocol: %d, but UDP header too small", src, dst, transProto)
		}
		udp := header.UDP(pk.TransportHeader)
		if fragmentOffset == 0 {
			srcPort = udp.SourcePort()
			dstPort = udp.DestinationPort()
			details = fmt.Sprintf("xsum: 0x%x", udp.Checksum())
			size -= header.UDPMinimumSize
		}

	case header.TCPProtocolNumber:
		transName = "tcp"
		if len(pk.TransportHeader) < header.TCPMinimumSize {
			return fmt.Sprintf("%v -> %v transport protocol: %d, but TCP header too small", src, dst, transProto)
		}
		tcp := header.TCP(pk.TransportHeader)
		if fragmentOffset == 0 {
			offset := int(tcp.DataOffset())
			if offset < header.TCPMinimumSize {
				details += fmt.Sprintf("invalid packet: tcp data offset too small %d", offset)
				break
			}
			if transportSize := len(pk.TransportHeader) + pk.Data.Size(); offset > transportSize && !moreFragments {
				details += fmt.Sprintf("invalid packet: tcp data offset %d larger than packet buffer length %d", offset, transportSize)
				break
			}

			srcPort = tcp.SourcePort()
			dstPort = tcp.DestinationPort()
			size -= uint16(offset)

			// Initialize the TCP flags.
			flags := tcp.Flags()
			flagsStr := []byte("FSRPAU")
			for i := range flagsStr {
				if flags&(1<<uint(i)) == 0 {
					flagsStr[i] = ' '
				}
			}
			details = fmt.Sprintf("flags:0x%02x (%v) seqnum: %v ack: %v win: %v xsum:0x%x", flags, string(flagsStr), tcp.SequenceNumber(), tcp.AckNumber(), tcp.WindowSize(), tcp.Checksum())
			if flags&header.TCPFlagSyn != 0 {
				details += fmt.Sprintf(" options: %+v", header.ParseSynOptions(tcp.Options(), flags&header.TCPFlagAck != 0))
			} else {
				details += fmt.Sprintf(" options: %+v", tcp.ParsedOptions())
			}
		}

	default:
		return fmt.Sprintf("%v -> %v unknown transport protocol: %d", src, dst, transProto)
	}

	return fmt.Sprintf("%s %v:%v -> %v:%v len:%d id:%04x %s", transName, src, srcPort, dst, dstPort, size, id, details)
}

// noCopy may be embedded into structs which must not be copied
// after the first use.
//
// See https://golang.org/issues/8005#issuecomment-190753527
// for details.
type noCopy struct{}

// Lock is a no-op used by -copylocks checker from `go vet`.
func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
