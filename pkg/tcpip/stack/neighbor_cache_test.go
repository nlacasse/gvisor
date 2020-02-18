// Copyright 2019 The gVisor Authors.
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

package stack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// entryStoreSize is the default amount of entries that will be generated and
	// added to the entry store. This number needs to be larger than the size of
	// the neighbor cache to give ample opportunity for verifying behavior during
	// cache overflows. Four times the size of the neighbor cache allows for
	// three complete cache overflows.
	entryStoreSize = 4 * neighborCacheSize

	// typicalLatency is the typical latency for an ARP or NDP packet to travel
	// to a router and back.
	typicalLatency = time.Millisecond

	// testEntryBroadcastAddr is a special address that indicates a packet should
	// be sent to all nodes.
	testEntryBroadcastAddr = tcpip.Address("broadcast")

	// testEntryLocalAddr is the source address of neighbor probes.
	testEntryLocalAddr = tcpip.Address("local_addr")

	// testEntryBroadcastLinkAddr is a special link address sent back to
	// multicast neighbor probes.
	testEntryBroadcastLinkAddr = tcpip.LinkAddress("mac_broadcast")
)

var (
	// eventDiffOpts are the options passed to cmp.Diff to compare neighbor
	// entries. The UpdatedAt field is ignored due to a lack of a deterministic
	// method to predict the time that an event will be dispatched.
	entryDiffOpts = cmpopts.IgnoreFields(NeighborEntry{}, "UpdatedAt")
)

func newTestNeighborCache(nudDisp NUDDispatcher, config NUDConfigurations, clock tcpip.Clock) *neighborCache {
	config.resetInvalidFields()
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	c := &neighborCache{
		nic: &NIC{
			stack: &Stack{
				clock:   clock,
				nudDisp: nudDisp,
			},
			id: 1,
		},
		state: NewNUDState(config, rng),
	}
	c.mu.cache = make(map[tcpip.Address]*neighborEntry, neighborCacheSize)
	return c
}

// testEntryStore contains a set of IP to NeighborEntry mappings.
type testEntryStore struct {
	mu struct {
		sync.RWMutex

		entries map[tcpip.Address]NeighborEntry
	}
}

func toAddress(i int) tcpip.Address {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint8(1))
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, uint16(i))
	return tcpip.Address(buf.String())
}

func toLinkAddress(i int) tcpip.LinkAddress {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint8(1))
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, uint32(i))
	return tcpip.LinkAddress(buf.String())
}

// newTestEntryStore returns a testEntryStore pre-populated with entries.
func newTestEntryStore() *testEntryStore {
	entries := make(map[tcpip.Address]NeighborEntry)
	for i := 0; i < entryStoreSize; i++ {
		addr := toAddress(i)
		linkAddr := toLinkAddress(i)

		entries[addr] = NeighborEntry{
			Addr:      addr,
			LocalAddr: testEntryLocalAddr,
			LinkAddr:  linkAddr,
		}
	}
	store := &testEntryStore{}
	store.mu.entries = entries
	return store
}

// size returns the amount of entries in the store.
func (s *testEntryStore) size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.mu.entries)
}

// entry returns the entry at index i. Returns an empty entry and false if i is
// out of bounds.
func (s *testEntryStore) entry(i int) (NeighborEntry, bool) {
	addr := toAddress(i)
	return s.entryByAddr(addr)
}

// entryByAddr returns the entry matching addr for situations when the index is
// not available. Returns an empty entry and false if no entries match addr.
func (s *testEntryStore) entryByAddr(addr tcpip.Address) (NeighborEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.mu.entries[addr]
	return entry, ok
}

// entries returns all entries in the store.
func (s *testEntryStore) entries() []NeighborEntry {
	entries := make([]NeighborEntry, 0, len(s.mu.entries))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := 0; i < entryStoreSize; i++ {
		addr := toAddress(i)
		if entry, ok := s.mu.entries[addr]; ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

// set modifies the link addresses of an entry.
func (s *testEntryStore) set(i int, linkAddr tcpip.LinkAddress) {
	addr := toAddress(i)
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.mu.entries[addr]; ok {
		entry.LinkAddr = linkAddr
		s.mu.entries[addr] = entry
	}
}

// testLinkAddressResolver implements LinkAddressResolver to emulate sending a
// neighbor probe.
type testLinkAddressResolver struct {
	clock                tcpip.Clock
	neigh                *neighborCache
	entries              *testEntryStore
	delay                time.Duration
	onLinkAddressRequest func()
}

var _ LinkAddressResolver = (*testLinkAddressResolver)(nil)

func (r *testLinkAddressResolver) LinkAddressRequest(addr, localAddr tcpip.Address, linkAddr tcpip.LinkAddress, linkEP LinkEndpoint) *tcpip.Error {
	r.clock.AfterFunc(nil, r.delay, func() { r.fakeRequest(addr) })
	if f := r.onLinkAddressRequest; f != nil {
		f()
	}
	return nil
}

func (r *testLinkAddressResolver) fakeRequest(addr tcpip.Address) {
	if e, ok := r.entries.entryByAddr(addr); ok {
		r.neigh.HandleConfirmation(addr, e.LinkAddr, ReachabilityConfirmationFlags{
			Solicited: true,
			Override:  false,
			IsRouter:  false,
		})
	}
}

func (*testLinkAddressResolver) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if addr == testEntryBroadcastAddr {
		return testEntryBroadcastLinkAddr, true
	}
	return "", false
}

func (*testLinkAddressResolver) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return 0
}

type entryEvent struct {
	nicID    tcpip.NICID
	address  tcpip.Address
	linkAddr tcpip.LinkAddress
	state    NeighborState
}

func TestCacheGetConfig(t *testing.T) {
	nudDisp := testNUDDispatcher{}
	c := DefaultNUDConfigurations()
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, c, &clock)

	if got, want := neigh.config(), c; got != want {
		t.Errorf("neigh.config()=%+v, want %+v", got, want)
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestCacheSetConfig(t *testing.T) {
	nudDisp := testNUDDispatcher{}
	c := DefaultNUDConfigurations()
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, c, &clock)

	c.BaseReachableTime = infiniteDuration
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	neigh.setConfig(c)

	if got, want := neigh.config(), c; got != want {
		t.Errorf("neigh.config()=%+v, want %+v", got, want)
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestCacheEntry(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	nudDisp := testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	a, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}
	_, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}

	clock.advanceAll()
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.events = nil
	nudDisp.mu.Unlock()

	_, _, err = neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	// No more events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

// TestCacheEntryNoLinkAddress verifies calling entry() without a
// LinkAddressResolver returns ErrNoLinkAddress.
func TestCacheEntryNoLinkAddress(t *testing.T) {
	nudDisp := testNUDDispatcher{}
	c := DefaultNUDConfigurations()
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, c, &clock)
	store := newTestEntryStore()

	a, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}
	_, _, err := neigh.entry(a.Addr, a.LocalAddr, nil, nil)
	if err != tcpip.ErrNoLinkAddress {
		t.Errorf("neigh.entry(%q) should return ErrNoLinkAddress, got %v", a.Addr, err)
	}

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestCacheRemoveEntry(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1
	config.UnreachableTime = infiniteDuration // stay in failed

	nudDisp := testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	a, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}
	_, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}

	clock.advanceAll()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.events = nil
	nudDisp.mu.Unlock()

	neigh.removeEntry(a.Addr)
	clock.advanceAll()

	wantEvents = []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	_, _, err = neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
}

type testContext struct {
	clock   *fakeClock
	neigh   *neighborCache
	store   *testEntryStore
	linkRes *testLinkAddressResolver
	nudDisp *testNUDDispatcher
}

func newTestContext(c NUDConfigurations) testContext {
	nudDisp := &testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(nudDisp, c, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	return testContext{
		clock:   &clock,
		neigh:   neigh,
		store:   store,
		linkRes: linkRes,
		nudDisp: nudDisp,
	}
}

type overflowOptions struct {
	expectedDynamicEntryCount int
	startAtEntryIndex         int
}

func (c *testContext) overflowCache(opts overflowOptions) error {
	// Fill the neighbor cache to capacity to verify the LRU eviction strategy is
	// working properly after the entry removal.
	offset := opts.startAtEntryIndex - opts.expectedDynamicEntryCount
	for i := opts.startAtEntryIndex; i < neighborCacheSize+offset; i++ {
		a, ok := c.store.entry(i)
		if !ok {
			return fmt.Errorf("c.store.entry(%d) not found", i)
		}
		if _, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil); err != tcpip.ErrWouldBlock {
			return fmt.Errorf("fill %d, neigh.entry(%q) should block, got %v", i, a.Addr, err)
		}
		c.clock.advanceAll()
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      a.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      a.Addr,
				LinkAddr:  a.LinkAddr,
				State:     Reachable,
			},
		}
		c.nudDisp.mu.Lock()
		if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
			return fmt.Errorf("got invalid events (-got, +want):\n%s", diff)
		}
		c.nudDisp.mu.events = nil
		c.nudDisp.mu.Unlock()
	}

	// Keep adding more entries
	for i := neighborCacheSize + offset; i < c.store.size(); i++ {
		a, ok := c.store.entry(i)
		if !ok {
			return fmt.Errorf("c.store.entry(%d) not found", i)
		}
		_, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
		if err != tcpip.ErrWouldBlock {
			return fmt.Errorf("overflow %d, neigh.entry(%q) should block, got %v", i, a.Addr, err)
		}
		c.clock.advanceAll()
		removedEntry, ok := c.store.entry(i - neighborCacheSize)
		if !ok {
			return fmt.Errorf("c.store.entry(%d) not found", i-neighborCacheSize)
		}
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Addr:      removedEntry.Addr,
				LinkAddr:  removedEntry.LinkAddr,
				State:     Reachable,
			},
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      a.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      a.Addr,
				LinkAddr:  a.LinkAddr,
				State:     Reachable,
			},
		}
		c.nudDisp.mu.Lock()
		if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
			return fmt.Errorf("got invalid events (-got, +want):\n%s", diff)
		}
		c.nudDisp.mu.events = nil
		c.nudDisp.mu.Unlock()
	}

	// Expect to find only the most recent entries.
	for i := c.store.size() - neighborCacheSize; i < c.store.size(); i++ {
		a, ok := c.store.entry(i)
		if !ok {
			return fmt.Errorf("c.store.entry(%d) not found", i)
		}
		e, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
		if err != nil {
			return fmt.Errorf("check %d, neigh.entry(%q)=%q, got error: %v", i, a.Addr, e.LinkAddr, err)
		}
		if e.LinkAddr != a.LinkAddr {
			return fmt.Errorf("check %d, neigh.entry(%q)=%q, want %q", i, a.Addr, e.LinkAddr, a.LinkAddr)
		}
	}

	// The earliest entries should no longer be in the cache. Order of the
	// entries reported by entries() is undeterministic, so entries have to be
	// searched for.
	entries := c.neigh.entries()
	entryByAddr, err := mapByAddr(entries)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for i := opts.startAtEntryIndex; i < c.store.size()-neighborCacheSize; i++ {
		a, ok := c.store.entry(i)
		if !ok {
			return fmt.Errorf("c.store.entry(%d) not found", i)
		}
		if _, ok := entryByAddr[a.Addr]; ok {
			return fmt.Errorf("check %d, neigh.entry(%q), got exists, want nonexistent", i, a.Addr)
		}
	}

	// No more events should have been dispatched.
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, []testEntryEventInfo(nil)); diff != "" {
		return fmt.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.Unlock()

	return nil
}

// TestCacheOverflow verifies that the LRU cache eviction strategy respects the
// dynamic entry count.
func TestCacheOverflow(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1
	config.UnreachableTime = infiniteDuration // stay in failed

	c := newTestContext(config)
	opts := overflowOptions{
		startAtEntryIndex:         0,
		expectedDynamicEntryCount: 0,
	}
	if err := c.overflowCache(opts); err != nil {
		t.Error(err)
	}
}

// TestCacheRemoveEntryThenOverflow verifies that the LRU cache eviction
// strategy respects the dynamic entry count when an entry is removed.
func TestCacheRemoveEntryThenOverflow(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	c := newTestContext(config)

	// Add a dynamic entry
	a, ok := c.store.entry(0)
	if !ok {
		t.Fatalf("c.store.entry(0) not found")
	}
	_, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	c.clock.advanceAll()
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.events = nil
	c.nudDisp.mu.Unlock()

	// Remove the entry
	c.neigh.removeEntry(a.Addr)
	c.clock.advanceAll()
	wantEvents = []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.events = nil
	c.nudDisp.mu.Unlock()

	opts := overflowOptions{
		startAtEntryIndex:         0,
		expectedDynamicEntryCount: 0,
	}
	if err := c.overflowCache(opts); err != nil {
		t.Error(err)
	}
}

// TestCacheDuplicateStaticEntryWithSameLinkAddress verifies that adding a
// duplicate static entry with the same link address does not dispatch any
// events.
func TestCacheDuplicateStaticEntryWithSameLinkAddress(t *testing.T) {
	config := DefaultNUDConfigurations()
	c := newTestContext(config)

	// Add a static entry
	a, ok := c.store.entry(0)
	if !ok {
		t.Fatalf("c.store.entry(0) not found")
	}
	staticLinkAddr := a.LinkAddr + "static"
	c.neigh.addStaticEntry(a.Addr, staticLinkAddr)
	c.clock.advanceAll()
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  staticLinkAddr,
			State:     Static,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.events = nil
	c.nudDisp.mu.Unlock()

	// Remove the static entry that was just added
	c.neigh.addStaticEntry(a.Addr, staticLinkAddr)
	c.clock.advanceAll()

	// No more events should have been dispatched.
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.Unlock()
}

// TestCacheDuplicateStaticEntryWithDifferentLinkAddress verifies that adding a
// duplicate static entry with a different link address dispatches a change
// event.
func TestCacheDuplicateStaticEntryWithDifferentLinkAddress(t *testing.T) {
	config := DefaultNUDConfigurations()
	c := newTestContext(config)

	// Add a static entry
	a, ok := c.store.entry(0)
	if !ok {
		t.Fatalf("c.store.entry(0) not found")
	}
	staticLinkAddr := a.LinkAddr + "static"
	c.neigh.addStaticEntry(a.Addr, staticLinkAddr)
	c.clock.advanceAll()
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  staticLinkAddr,
			State:     Static,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.events = nil
	c.nudDisp.mu.Unlock()

	// Remove the static entry that was just added
	staticLinkAddr += "duplicate"
	c.neigh.addStaticEntry(a.Addr, staticLinkAddr)
	c.clock.advanceAll()
	wantEvents = []testEntryEventInfo{
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  staticLinkAddr,
			State:     Static,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.Unlock()
}

// TestCacheRemoveStaticEntryThenOverflow verifies that the LRU cache eviction
// strategy respects the dynamic entry count when a static entry is added then
// removed. In this case, the dynamic entry count shouldn't have been touched.
func TestCacheRemoveStaticEntryThenOverflow(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	c := newTestContext(config)

	// Add a static entry
	a, ok := c.store.entry(0)
	if !ok {
		t.Fatalf("c.store.entry(0) not found")
	}
	staticLinkAddr := a.LinkAddr + "static"
	c.neigh.addStaticEntry(a.Addr, staticLinkAddr)
	c.clock.advanceAll()
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  staticLinkAddr,
			State:     Static,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.events = nil
	c.nudDisp.mu.Unlock()

	// Remove the static entry that was just added
	c.neigh.removeEntry(a.Addr)
	c.clock.advanceAll()
	wantEvents = []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  staticLinkAddr,
			State:     Static,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.events = nil
	c.nudDisp.mu.Unlock()

	opts := overflowOptions{
		startAtEntryIndex:         0,
		expectedDynamicEntryCount: 0,
	}
	if err := c.overflowCache(opts); err != nil {
		t.Error(err)
	}
}

// TestCacheOverwriteWithStaticEntryThenOverflow verifies that the LRU cache
// eviction strategy keeps count of the dynamic entry count when an entry is
// overwritten by a static entry. Static entries should not count towards the
// size of the LRU cache.
func TestCacheOverwriteWithStaticEntryThenOverflow(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	c := newTestContext(config)

	// Add a dynamic entry
	a, ok := c.store.entry(0)
	if !ok {
		t.Fatalf("c.store.entry(0) not found")
	}
	_, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	c.clock.advanceAll()
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.events = nil
	c.nudDisp.mu.Unlock()

	// Override the entry with a static one using the same address
	staticLinkAddr := a.LinkAddr + "static"
	c.neigh.addStaticEntry(a.Addr, staticLinkAddr)
	c.clock.advanceAll()
	wantEvents = []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  staticLinkAddr,
			State:     Static,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.events = nil
	c.nudDisp.mu.Unlock()

	opts := overflowOptions{
		startAtEntryIndex:         1,
		expectedDynamicEntryCount: 0,
	}
	if err := c.overflowCache(opts); err != nil {
		t.Error(err)
	}

	// The static entry should be in the cache.
	e, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
	if err != nil {
		t.Errorf("expected static neighbor entry for %q, got error: %v", a.Addr, err)
	}
	if got, want := e.LinkAddr, staticLinkAddr; got != want {
		t.Errorf("got e.LinkAddr=%q, want %q", got, want)
	}
	if got, want := e.State, Static; got != want {
		t.Errorf("got e.State=%q, want %q", got, want)
	}
	c.clock.advanceAll()

	// No more events should have been dispatched.
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.Unlock()
}

func TestCacheNotifiesWaker(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	nudDisp := testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	w := sleep.Waker{}
	s := sleep.Sleeper{}
	const wakerID = 1
	s.AddWaker(&w, wakerID)

	a, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}
	_, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, &w)
	if err != tcpip.ErrWouldBlock {
		t.Fatalf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	if doneCh == nil {
		t.Fatalf("expected channel from neigh.entry(%q), got none", a.Addr)
	}
	clock.advanceAll()

	select {
	case <-doneCh:
	default:
		t.Fatal("expected notification from done channel")
	}

	id, ok := s.Fetch(false /* block */)
	if !ok {
		t.Error("expected waker to be notified")
	}
	if id != wakerID {
		t.Errorf("got s.Fetch(false)=%d, want=%d", id, wakerID)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestCacheRemoveWaker(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	nudDisp := testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	w := sleep.Waker{}
	s := sleep.Sleeper{}
	const wakerID = 1
	s.AddWaker(&w, wakerID)

	a, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}
	_, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, &w)
	if err != tcpip.ErrWouldBlock {
		t.Fatalf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	if doneCh == nil {
		t.Fatalf("expected channel from neigh.entry(%q), got none", a.Addr)
	}

	// Remove the waker before the neighbor cache has the opportunity to send a
	// notification.
	neigh.removeWaker(a.Addr, &w)
	clock.advanceAll()

	select {
	case <-doneCh:
	default:
		t.Fatal("expected notification from done channel")
	}

	id, ok := s.Fetch(false /* block */)
	if ok {
		t.Error("unexpected notification from waker")
	}
	if id == wakerID {
		t.Errorf("got s.Fetch(false)=%d, want anything but %d", id, wakerID)
	}

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestCacheAddStaticEntry(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	c := newTestContext(config)

	c.neigh.addStaticEntry(entryTestAddr1, entryTestLinkAddr1)
	e, _, err := c.neigh.entry(entryTestAddr1, "", nil, nil)
	if err != nil {
		t.Errorf("c.neigh.entry(%q) returned error %s", entryTestAddr1, err)
	}
	if got, want := e.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("got c.neigh.entry(%q).LinkAddr=%q, want %q", entryTestAddr1, got, want)
	}
	c.clock.advanceAll()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Static,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.events = nil
	c.nudDisp.mu.Unlock()

	opts := overflowOptions{
		startAtEntryIndex:         0,
		expectedDynamicEntryCount: 0,
	}
	if err := c.overflowCache(opts); err != nil {
		t.Error(err)
	}
}

func TestCacheRemoveStaticEntry(t *testing.T) {
	nudDisp := testNUDDispatcher{}
	c := DefaultNUDConfigurations()
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, c, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	a, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}
	neigh.addStaticEntry(a.Addr, a.LinkAddr)
	clock.advanceAll()
	neigh.removeEntry(a.Addr)
	clock.advanceAll()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Static,
		},
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Static,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	_, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
}

func TestCacheStaticEntryOverridesDynamicEntry(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	nudDisp := testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	// Add a dynamic entry.
	a, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}
	_, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	clock.advanceAll()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.events = nil
	nudDisp.mu.Unlock()

	e, _, err := neigh.entry(a.Addr, "", nil, nil)
	if err != nil {
		t.Errorf("neigh.entry(%q) returned error %s", a.Addr, err)
	}

	a.State = Reachable
	if diff := cmp.Diff(e, a, entryDiffOpts); diff != "" {
		t.Errorf("invalid neighbor entry received (-got, +want):\n%s", diff)
	}
	clock.advanceAll()

	// Replace the dynamic entry with a static one.
	neigh.addStaticEntry(a.Addr, entryTestLinkAddr1)
	clock.advanceAll()

	e, _, err = neigh.entry(a.Addr, "", nil, nil)
	if err != nil {
		t.Errorf("neigh.entry(%q) returned error %s", a.Addr, err)
	}

	wantEntry := NeighborEntry{
		Addr:     a.Addr,
		LinkAddr: entryTestLinkAddr1,
		State:    Static,
	}
	if diff := cmp.Diff(e, wantEntry, entryDiffOpts); diff != "" {
		t.Errorf("invalid neighbor entry received (-got, +want):\n%s", diff)
	}
	clock.advanceAll()

	wantEvents = []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  entryTestLinkAddr1,
			State:     Static,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestCacheClear(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	nudDisp := testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	// Add a dynamic entry.
	a, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}
	_, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	clock.advanceAll()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.events = nil
	nudDisp.mu.Unlock()

	// Add a static entry.
	neigh.addStaticEntry(entryTestAddr1, entryTestLinkAddr1)
	clock.advanceAll()

	wantEvents = []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Static,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.events = nil
	nudDisp.mu.Unlock()

	// Clear shoud remove both dynamic and static entries.
	neigh.clear()
	clock.advanceAll()

	// Remove events dispatched from clear() have no deterministic order.
	events := make(map[tcpip.Address]testEntryEventInfo)
	nudDisp.mu.Lock()
	if len(nudDisp.mu.events) < 2 {
		t.Fatalf("expected two more events, got %d", len(nudDisp.mu.events))
	}
	for i := 0; i < 2; i++ {
		e := nudDisp.mu.events[i]
		if existing, ok := events[e.Addr]; ok {
			if diff := cmp.Diff(existing, e); diff != "" {
				t.Fatalf("duplicate event found (-existing +got):\n%s", diff)
			} else {
				t.Fatalf("exact event duplicate found for %s", e)
			}
		}
		events[e.Addr] = e
	}
	nudDisp.mu.events = nudDisp.mu.events[2:]
	nudDisp.mu.Unlock()

	gotEvent, ok := events[a.Addr]
	if !ok {
		t.Fatalf("expected event with Addr=%q", a.Addr)
	}

	wantEvent := testEntryEventInfo{
		EventType: entryTestRemoved,
		NICID:     1,
		Addr:      a.Addr,
		LinkAddr:  a.LinkAddr,
		State:     Reachable,
	}
	if diff := cmp.Diff(gotEvent, wantEvent, eventDiffOpts); diff != "" {
		t.Errorf("invalid event received (-got, +want):\n%s", diff)
	}

	gotEvent, ok = events[entryTestAddr1]
	if !ok {
		t.Fatalf("expected event with Addr=%q", a.Addr)
	}

	wantEvent = testEntryEventInfo{
		EventType: entryTestRemoved,
		NICID:     1,
		Addr:      entryTestAddr1,
		LinkAddr:  entryTestLinkAddr1,
		State:     Static,
	}
	if diff := cmp.Diff(gotEvent, wantEvent, eventDiffOpts); diff != "" {
		t.Errorf("invalid event received (-got, +want):\n%s", diff)
	}

	// No more events should have been dispatched. Comparing against an empty
	// slice (not nil) because the previous code shifts from the events slice.
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, []testEntryEventInfo{}); diff != "" {
		t.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func mapByAddr(entries []NeighborEntry) (map[tcpip.Address]NeighborEntry, error) {
	entryByAddr := make(map[tcpip.Address]NeighborEntry)

	for _, e := range entries {
		if existing, ok := entryByAddr[e.Addr]; ok {
			if diff := cmp.Diff(existing, e); diff != "" {
				return nil, fmt.Errorf("duplicate neighbor entry found (-existing +got):\n%s", diff)
			}
			return nil, fmt.Errorf("exact neighbor entry duplicate found:\n%s", e)
		}
		entryByAddr[e.Addr] = e
	}

	return entryByAddr, nil
}

// TestCacheClearThenOverflow verifies that the LRU cache eviction strategy
// keeps count of the dynamic entry count when all entries are cleared.
func TestCacheClearThenOverflow(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	c := newTestContext(config)

	// Add a dynamic entry
	a, ok := c.store.entry(0)
	if !ok {
		t.Fatalf("c.store.entry(0) not found")
	}
	_, _, err := c.neigh.entry(a.Addr, a.LocalAddr, c.linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	c.clock.advanceAll()
	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     1,
			Addr:      a.Addr,
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.events = nil
	c.nudDisp.mu.Unlock()

	// Clear the cache.
	c.neigh.clear()
	c.clock.advanceAll()
	wantEvents = []testEntryEventInfo{
		{
			EventType: entryTestRemoved,
			NICID:     1,
			Addr:      a.Addr,
			LinkAddr:  a.LinkAddr,
			State:     Reachable,
		},
	}
	c.nudDisp.mu.Lock()
	if diff := cmp.Diff(c.nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	c.nudDisp.mu.events = nil
	c.nudDisp.mu.Unlock()

	opts := overflowOptions{
		startAtEntryIndex:         0,
		expectedDynamicEntryCount: 0,
	}
	if err := c.overflowCache(opts); err != nil {
		t.Error(err)
	}
}

func TestCacheKeepFrequentlyUsed(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	nudDisp := testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	frequentlyUsedEntry, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}

	// Fill the neighbor cache to capacity
	for i := 0; i < neighborCacheSize; i++ {
		a, ok := store.entry(i)
		if !ok {
			t.Fatalf("store.entry(%d) not found", i)
		}
		_, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
		if err != tcpip.ErrWouldBlock {
			t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
		}
		clock.advanceAll()
		select {
		case <-doneCh:
		default:
			t.Fatalf("expected notification from done channel returned by neigh.entry(%q)", a.Addr)
		}
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      a.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      a.Addr,
				LinkAddr:  a.LinkAddr,
				State:     Reachable,
			},
		}
		nudDisp.mu.Lock()
		if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
			t.Fatalf("got invalid events (-got, +want):\n%s", diff)
		}
		nudDisp.mu.events = nil
		nudDisp.mu.Unlock()
	}
	// Keep adding more entries
	for i := neighborCacheSize; i < store.size(); i++ {
		// Periodically refresh the frequently used entry
		if i%(neighborCacheSize/2) == 0 {
			_, _, err := neigh.entry(frequentlyUsedEntry.Addr, frequentlyUsedEntry.LocalAddr, linkRes, nil)
			if err != nil {
				t.Errorf("got error while refreshing recently used entry: %v", err)
			}
		}

		a, ok := store.entry(i)
		if !ok {
			t.Fatalf("store.entry(%d) not found", i)
		}
		_, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
		if err != tcpip.ErrWouldBlock {
			t.Errorf("neigh.entry(%q) should block, got %v", a.Addr, err)
		}
		clock.advanceAll()
		select {
		case <-doneCh:
		default:
			t.Fatalf("expected notification from done channel returned by neigh.entry(%q)", a.Addr)
		}
		removedEntry, ok := store.entry(i - neighborCacheSize + 1)
		if !ok {
			t.Fatalf("store.entry(%d) not found", i-neighborCacheSize+1)
		}
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Addr:      removedEntry.Addr,
				LinkAddr:  removedEntry.LinkAddr,
				State:     Reachable,
			},
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      a.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      a.Addr,
				LinkAddr:  a.LinkAddr,
				State:     Reachable,
			},
		}
		nudDisp.mu.Lock()
		if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
			t.Fatalf("got invalid events (-got, +want):\n%s", diff)
		}
		nudDisp.mu.events = nil
		nudDisp.mu.Unlock()
	}
	// Expect to find only the most recent entries.
	for i := store.size() - neighborCacheSize + 1; i < store.size(); i++ {
		a, ok := store.entry(i)
		if !ok {
			t.Fatalf("store.entry(%d) not found", i)
		}
		e, _, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
		if err != nil {
			t.Errorf("insert %d, neigh.entry(%q)=%q, got error: %v", i, a.Addr, e.LinkAddr, err)
		}
		if e.LinkAddr != a.LinkAddr {
			t.Errorf("insert %d, neigh.entry(%q)=%q, want %q", i, a.Addr, e.LinkAddr, a.LinkAddr)
		}
	}
	// The earliest entries should no longer be in the cache. Order of the
	// entries reported by entries() is undeterministic, so entries have to be
	// searched for.
	entries := neigh.entries()
	entryByAddr, err := mapByAddr(entries)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < store.size()-neighborCacheSize; i++ {
		a, ok := store.entry(i)
		if !ok {
			t.Fatalf("store.entry(%d) not found", i)
		}
		if _, ok := entryByAddr[a.Addr]; ok {
			t.Errorf("check %d, neigh.entry(%q), got exists, want nonexistent", i, a.Addr)
		}
	}
	// The frequently used entry should be in the cache
	if _, ok := entryByAddr[frequentlyUsedEntry.Addr]; !ok {
		t.Error("expected frequently used entry to exist")
	}

	// No more events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestCacheConcurrent(t *testing.T) {
	const concurrentProcesses = 16

	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	nudDisp := testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	storeEntries := store.entries()
	for i, e := range storeEntries {
		e := e // capture range variable
		for r := 0; r < concurrentProcesses; r++ {
			clock.AfterFunc(nil, time.Duration(r*concurrentProcesses+i)*time.Millisecond, func() {
				_, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil)
				if err != nil && err != tcpip.ErrWouldBlock {
					t.Errorf("neigh.entry(%q) want success or ErrWouldBlock, got %v", e.Addr, err)
				}
			})
		}
		clock.advanceAll()
	}

	entries := make(map[tcpip.Address]NeighborEntry)
	for _, e := range neigh.entries() {
		entries[e.Addr] = e
	}

	// All goroutines add in the same order and add more values than can fit in
	// the cache. Our eviction strategy requires that the last entries are
	// present, up to the size of the neighbor cache, and the rest are missing.
	for i := 0; i < neighborCacheSize; i++ {
		e, ok := store.entry(store.size() - 1 - i)
		if !ok {
			t.Fatalf("store.entry(%d) not found", store.size()-1-i)
		}
		if entry, ok := entries[e.Addr]; ok {
			if entry.LinkAddr != e.LinkAddr {
				t.Errorf("neigh.entry(%q)=%q, want %q", e.Addr, entry.LinkAddr, e.LinkAddr)
			}
		} else {
			t.Errorf("neigh.entry(%q) does not exists, want exists", e.Addr)
		}
	}

	for i := 0; i < store.size()-neighborCacheSize; i++ {
		e, ok := store.entry(i)
		if !ok {
			t.Fatalf("store.entry(%d) not found", i)
		}
		if _, ok := entries[e.Addr]; ok {
			t.Errorf("neigh.entry(%q) exists, want does not exist", e.Addr)
		}
	}
}

func TestCacheReplace(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	nudDisp := testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	// Add an entry
	a, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}
	e, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Fatalf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	clock.advanceAll()
	select {
	case <-doneCh:
	default:
		t.Fatalf("expected notification from done channel returned by neigh.entry(%q)", a.Addr)
	}

	// Verify the entry exists
	e, doneCh, err = neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != nil {
		t.Fatalf("neigh.entry(%q) should not error, got %v", a.Addr, err)
	}
	if doneCh != nil {
		t.Fatalf("neigh.entry(%q) unexpectedly returned done channel", a.Addr)
	}
	if e.State != Reachable {
		t.Errorf("neigh.entry(%q).State = %q, want %q", a.Addr, e.State, Reachable)
	}
	if e.LinkAddr != a.LinkAddr {
		t.Errorf("neigh.entry(%q).LinkAddr = %q, want %q", a.Addr, e.LinkAddr, a.LinkAddr)
	}
	clock.advanceAll()

	// Notify of a link address change
	var updatedLinkAddr tcpip.LinkAddress
	{
		a, ok := store.entry(1)
		if !ok {
			t.Fatalf("store.entry(1) not found")
		}
		updatedLinkAddr = a.LinkAddr
	}
	store.set(0, updatedLinkAddr)
	neigh.HandleConfirmation(a.Addr, updatedLinkAddr, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	e, doneCh, err = neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	if err != tcpip.ErrWouldBlock {
		t.Fatalf("neigh.entry(%q) should block, got %v", a.Addr, err)
	}
	clock.advanceAll()
	select {
	case <-doneCh:
	default:
		t.Fatalf("expected notification from done channel returned by neigh.entry(%q)", a.Addr)
	}

	// Verify the entry's new link address
	e, _, err = neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
	clock.advanceAll()
	if err != nil {
		t.Errorf("neigh.entry(%q) should exist, got %v", a.Addr, err)
	}
	if e.LinkAddr != updatedLinkAddr {
		t.Errorf("neigh.entry(%q).LinkAddr = %q, want %q", a.Addr, e.LinkAddr, updatedLinkAddr)
	}
}

func TestCacheResolution(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1

	nudDisp := testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	// Fill the neighbor cache to full capacity
	for i := 0; i < neighborCacheSize; i++ {
		e, ok := store.entry(i)
		if !ok {
			t.Fatalf("store.entry(%d) not found", i)
		}
		if _, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil); err != tcpip.ErrWouldBlock {
			t.Fatalf("neigh.entry(%q) got error: %v, want error: %v", e.Addr, err, tcpip.ErrWouldBlock)
		}
		clock.advanceAll()
		got, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil)
		if err != nil {
			t.Errorf("unexpected error from neigh.entry(%q): %v", e.Addr, err)
		}
		if got.LinkAddr != e.LinkAddr {
			t.Errorf("got neigh.entry(%q)=%q, want %q", e.Addr, got.LinkAddr, e.LinkAddr)
		}
		clock.advanceAll()
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      e.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      e.Addr,
				LinkAddr:  e.LinkAddr,
				State:     Reachable,
			},
		}
		nudDisp.mu.Lock()
		if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
			t.Fatalf("got invalid events (-got, +want):\n%s", diff)
		}
		nudDisp.mu.events = nil
		nudDisp.mu.Unlock()
	}

	// Use the rest of the entries in the store
	for i := neighborCacheSize; i < store.size(); i++ {
		e, ok := store.entry(i)
		if !ok {
			t.Fatalf("store.entry(%d) not found", i)
		}
		if _, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil); err != tcpip.ErrWouldBlock {
			t.Fatalf("neigh.entry(%q) got error: %v, want error: %v", e.Addr, err, tcpip.ErrWouldBlock)
		}
		clock.advanceAll()
		got, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil)
		if err != nil {
			t.Errorf("unexpected error from neigh.entry(%q): %v", e.Addr, err)
		}
		if got.LinkAddr != e.LinkAddr {
			t.Errorf("got neigh.entry(%q)=%q, want %q", e.Addr, got.LinkAddr, e.LinkAddr)
		}
		clock.advanceAll()
		removedEntry, ok := store.entry(i - neighborCacheSize)
		if !ok {
			t.Fatalf("store.entry(%d) not found", i-neighborCacheSize)
		}
		wantEvents := []testEntryEventInfo{
			{
				EventType: entryTestRemoved,
				NICID:     1,
				Addr:      removedEntry.Addr,
				LinkAddr:  removedEntry.LinkAddr,
				State:     Reachable,
			},
			{
				EventType: entryTestAdded,
				NICID:     1,
				Addr:      e.Addr,
				State:     Incomplete,
			},
			{
				EventType: entryTestChanged,
				NICID:     1,
				Addr:      e.Addr,
				LinkAddr:  e.LinkAddr,
				State:     Reachable,
			},
		}
		nudDisp.mu.Lock()
		if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
			t.Fatalf("got invalid events (-got, +want):\n%s", diff)
		}
		nudDisp.mu.events = nil
		nudDisp.mu.Unlock()
	}

	// Check that after resolved, address stays in the cache and never returns WouldBlock.
	for i := 0; i < neighborCacheSize; i++ {
		e, ok := store.entry(store.size() - i - 1)
		if !ok {
			t.Fatalf("store.entry(%d) not found", store.size()-i-1)
		}
		got, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil)
		if err != nil {
			t.Errorf("neigh.entry(%q)=%q, got error: %v", e.Addr, got, err)
		}
		if got.LinkAddr != e.LinkAddr {
			t.Errorf("neigh.entry(%q)=%q, want %q", e.Addr, got.LinkAddr, e.LinkAddr)
		}
	}

	// No more events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestCacheResolutionFailed(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.BaseReachableTime = infiniteDuration // stay in reachable
	config.MinRandomFactor = 1
	config.MaxRandomFactor = 1
	config.UnreachableTime = infiniteDuration // stay in failed

	nudDisp := testNUDDispatcher{}
	clock := fakeClock{}
	neigh := newTestNeighborCache(&nudDisp, config, &clock)
	store := newTestEntryStore()

	var requestCount uint32
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
		onLinkAddressRequest: func() {
			atomic.AddUint32(&requestCount, 1)
		},
	}

	// First, sanity check that resolution is working
	e, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}
	if _, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("neigh.entry(%q) got error: %v, want error: %v", e.Addr, err, tcpip.ErrWouldBlock)
	}
	clock.advanceAll()
	got, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil)
	if err != nil {
		t.Errorf("unexpected error from neigh.entry(%q): %v", e.Addr, err)
	}
	if got.LinkAddr != e.LinkAddr {
		t.Errorf("got neigh.entry(%q)=%q, want %q", e.Addr, got.LinkAddr, e.LinkAddr)
	}
	clock.advanceAll()

	// Verify that address resolution for an unknown address returns ErrNoLinkAddress
	before := atomic.LoadUint32(&requestCount)

	e.Addr += "2"
	if _, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("neigh.entry(%q) got error: %v, want error: %v", e.Addr, err, tcpip.ErrWouldBlock)
	}
	clock.advanceAll()
	if _, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil); err != tcpip.ErrNoLinkAddress {
		t.Errorf("neigh.entry(%q) got error: %v, want error: %v", e.Addr, err, tcpip.ErrNoLinkAddress)
	}

	maxAttempts := neigh.config().MaxUnicastProbes
	if got, want := atomic.LoadUint32(&requestCount)-before, maxAttempts; got != want {
		t.Errorf("got link address request count = %d, want = %d", got, want)
	}
}

// TestCacheResolutionTimeout simulates sending MaxMulticastProbes probes and
// not retrieving a confirmation before the duration defined by
// MaxMulticastProbes * RetransmitTimer.
func TestCacheResolutionTimeout(t *testing.T) {
	config := DefaultNUDConfigurations()
	config.RetransmitTimer = time.Millisecond // small enough to cause timeout
	config.UnreachableTime = infiniteDuration // stay in failed

	clock := fakeClock{}
	neigh := newTestNeighborCache(nil, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   time.Minute, // large enough to cause timeout
	}

	e, ok := store.entry(0)
	if !ok {
		t.Fatalf("store.entry(0) not found")
	}
	if _, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil); err != tcpip.ErrWouldBlock {
		t.Fatalf("neigh.entry(%q) got error: %v, want error: %v", e.Addr, err, tcpip.ErrWouldBlock)
	}
	clock.advanceAll()
	if _, _, err := neigh.entry(e.Addr, e.LocalAddr, linkRes, nil); err != tcpip.ErrNoLinkAddress {
		t.Errorf("neigh.entry(%q) got error: %v, want error: %v", e.Addr, err, tcpip.ErrNoLinkAddress)
	}
}

// TestStaticResolution checks that static link addresses are resolved
// immediately and don't send resolution requests.
func TestStaticResolution(t *testing.T) {
	config := DefaultNUDConfigurations()
	clock := fakeClock{}
	neigh := newTestNeighborCache(nil, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   typicalLatency,
	}

	got, _, err := neigh.entry(testEntryBroadcastAddr, testEntryLocalAddr, linkRes, nil)
	if err != nil {
		t.Errorf("neigh.entry(%q)=%q, got error: %v", testEntryBroadcastAddr, got, err)
	}
	if got.LinkAddr != testEntryBroadcastLinkAddr {
		t.Errorf("neigh.entry(%q)=%q, want %q", testEntryBroadcastAddr, got.LinkAddr, testEntryBroadcastLinkAddr)
	}
}

func BenchmarkCacheClear(b *testing.B) {
	b.StopTimer()
	config := DefaultNUDConfigurations()
	clock := tcpip.StdClock{}
	neigh := newTestNeighborCache(nil, config, &clock)
	store := newTestEntryStore()
	linkRes := &testLinkAddressResolver{
		clock:   &clock,
		neigh:   neigh,
		entries: store,
		delay:   0,
	}

	// Clear for every possible size of the cache
	for cacheSize := 0; cacheSize < neighborCacheSize; cacheSize++ {
		// Fill the neighbor cache to capacity.
		for i := 0; i < cacheSize; i++ {
			a, ok := store.entry(i)
			if !ok {
				b.Fatalf("store.entry(%d) not found", i)
			}
			_, doneCh, err := neigh.entry(a.Addr, a.LocalAddr, linkRes, nil)
			if err != tcpip.ErrWouldBlock {
				b.Fatalf("expected neigh.entry(%q) to block", a.Addr)
			}
			if doneCh != nil {
				<-doneCh
			}
		}

		b.StartTimer()
		neigh.clear()
		b.StopTimer()
	}
}
