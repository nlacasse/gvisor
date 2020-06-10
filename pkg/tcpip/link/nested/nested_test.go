// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nested

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type parentEndpoint struct {
	Endpoint
}

var _ stack.LinkEndpoint = (*parentEndpoint)(nil)
var _ stack.NetworkDispatcher = (*parentEndpoint)(nil)

func (p *parentEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	p.NestedAttach(p, dispatcher)
}

type childEndpoint struct {
	dispatcher stack.NetworkDispatcher
}

var _ stack.LinkEndpoint = (*childEndpoint)(nil)

func (c *childEndpoint) MTU() uint32 {
	panic("implement me")
}

func (c *childEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	panic("implement me")
}

func (c *childEndpoint) MaxHeaderLength() uint16 {
	panic("implement me")
}

func (c *childEndpoint) LinkAddress() tcpip.LinkAddress {
	panic("implement me")
}

func (c *childEndpoint) WritePacket(*stack.Route, *stack.GSO, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) *tcpip.Error {
	panic("implement me")
}

func (c *childEndpoint) WritePackets(*stack.Route, *stack.GSO, stack.PacketBufferList, tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	panic("implement me")
}

func (c *childEndpoint) WriteRawPacket(buffer.VectorisedView) *tcpip.Error {
	panic("implement me")
}

func (c *childEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	c.dispatcher = dispatcher
}

func (c *childEndpoint) IsAttached() bool {
	return c.dispatcher != nil
}

func (c *childEndpoint) Wait() {
	panic("implement me")
}

type counterDispatcher struct {
	count int
}

var _ stack.NetworkDispatcher = (*counterDispatcher)(nil)

func (d *counterDispatcher) DeliverNetworkPacket(tcpip.LinkAddress, tcpip.LinkAddress, tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	d.count++
}

func TestNestedLinkEndpoint(t *testing.T) {

	const emptyAddress = tcpip.LinkAddress("")

	child := childEndpoint{}
	nested := parentEndpoint{Endpoint{LinkEndpoint: &child}}
	disp := counterDispatcher{}

	if child.IsAttached() {
		t.Fatal("child.IsAttached() = true, want = false")
	}
	if nested.IsAttached() {
		t.Fatal("nested.IsAttached() = true, want = false")
	}

	nested.Attach(&disp)
	if disp.count != 0 {
		t.Fatalf("got disp.count = %d, want = 0", disp.count)
	}
	if !child.IsAttached() {
		t.Fatal("child.IsAttached() = false, want = true")
	}
	if !nested.IsAttached() {
		t.Fatal("nested.IsAttached() = false, want = true")
	}

	nested.DeliverNetworkPacket(emptyAddress, emptyAddress, header.IPv4ProtocolNumber, &stack.PacketBuffer{})
	if disp.count != 1 {
		t.Fatalf("got disp.count = %d, want = 1", disp.count)
	}

	nested.Attach(nil)
	if child.IsAttached() {
		t.Fatal("child.IsAttached() = true, want = false")
	}
	if nested.IsAttached() {
		t.Fatal("nested.IsAttached() = true, want = false")
	}

	nested.DeliverNetworkPacket(emptyAddress, emptyAddress, header.IPv4ProtocolNumber, &stack.PacketBuffer{})
	if disp.count != 1 {
		t.Fatalf("got disp.count = %d, want = 1", disp.count)
	}

}
