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

// Package nested provides helpers to implement the pattern of nested stack.LinkEndpoints.
package nested

import (
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Endpoint is a helper struct meant to be embedded in other types
// that provide LinkEndpoint nesting. It is composed into a type that also
// implements stack.NetworkDispatcher and overrides stack.LinkEndpoint.Attach to
// call Endpoint.NestedAttach.
type Endpoint struct {
	stack.LinkEndpoint
	mu struct {
		sync.RWMutex
		dispatcher stack.NetworkDispatcher
	}
}

var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.GSOEndpoint = (*Endpoint)(nil)
var _ stack.NetworkDispatcher = (*Endpoint)(nil)

// NestedAttach helps types that embed Endpoint to implement
// LinkEndpoint.Attach. embedder is the NetworkDispatcher that will be given to
// the inner LinkEndpoint, and dispatcher is used in Endpoint's stack.NetworkDispatcher
// implementation. If dispatcher is nil, the inner LinkEndpoint will also receive a nil dispatcher
// instead of embedder.
func (e *Endpoint) NestedAttach(embedder, dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	e.mu.dispatcher = dispatcher
	e.mu.Unlock()
	if dispatcher == nil {
		embedder = nil
	}
	e.LinkEndpoint.Attach(embedder)
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.
func (e *Endpoint) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	d := e.mu.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(remote, local, protocol, pkt)
	}
}

// Attach implements stack.LinkEndpoint.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	panic("Embedders must override LinkEndpoint.Attach")
}

// IsAttached implements stack.LinkEndpoint.
func (e *Endpoint) IsAttached() bool {
	e.mu.RLock()
	d := e.mu.dispatcher != nil
	e.mu.RUnlock()
	return d
}

// GSOMaxSize implements stack.GSOEndpoint.
func (e *Endpoint) GSOMaxSize() uint32 {
	if e, ok := e.LinkEndpoint.(stack.GSOEndpoint); ok {
		return e.GSOMaxSize()
	}
	return 0
}
