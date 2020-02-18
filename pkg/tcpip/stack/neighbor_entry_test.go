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

package stack

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	entryTestNetNumber tcpip.NetworkProtocolNumber = math.MaxUint32

	entryTestNICID tcpip.NICID = 1
	entryTestAddr1             = tcpip.Address("\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
	entryTestAddr2             = tcpip.Address("\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")

	entryTestLinkAddr1 = tcpip.LinkAddress("\x0a\x00\x00\x00\x00\x01")
	entryTestLinkAddr2 = tcpip.LinkAddress("\x0a\x00\x00\x00\x00\x02")

	// entryTestNetDefaultMTU is the MTU, in bytes, used throughout the tests,
	// except where another value is explicitly used. It is chosen to match the
	// MTU of loopback interfaces on Linux systems.
	entryTestNetDefaultMTU = 65536

	// infiniteDuration indicates that a task will not occur in our lifetime.
	infiniteDuration = time.Duration(math.MaxInt64)
)

var (
	// eventDiffOpts are the options passed to cmp.Diff to compare entry events.
	// The UpdatedAt field is ignored due to a lack of a deterministic method to
	// predict the time that an event will be dispatched.
	eventDiffOpts = cmpopts.IgnoreFields(testEntryEventInfo{}, "UpdatedAt")
)

// The following unit tests exercise every state transition and verify its
// behavior with RFC 4681.
//
// | From       | To         | Cause                                      | Action          | Event   |
// | ========== | ========== | ========================================== | =============== | ======= |
// | Unknown    | Unknown    | Confirmation w/ unknown address            |                 | Added   |
// | Unknown    | Incomplete | Packet queued to unknown address           | Send probe      | Added   |
// | Unknown    | Stale      | Probe w/ unknown address                   |                 | Added   |
// | Incomplete | Incomplete | Retransmit timer expired                   | Send probe      | Changed |
// | Incomplete | Reachable  | Solicited confirmation                     | Notify wakers   | Changed |
// | Incomplete | Stale      | Unsolicited confirmation                   | Notify wakers   | Changed |
// | Incomplete | Failed     | Max probes sent without reply              | Notify wakers   | Removed |
// | Reachable  | Reachable  | Confirmation w/ different isRouter flag    | Update IsRouter |         |
// | Reachable  | Stale      | Reachable timer expired                    |                 | Changed |
// | Reachable  | Stale      | Probe or confirmation w/ different address |                 | Changed |
// | Stale      | Reachable  | Solicited override confirmation            | Update LinkAddr | Changed |
// | Stale      | Stale      | Override confirmation                      | Update LinkAddr | Changed |
// | Stale      | Stale      | Probe w/ different address                 | Update LinkAddr | Changed |
// | Stale      | Delay      | Packet sent                                |                 | Changed |
// | Delay      | Reachable  | Upper-layer confirmation                   |                 | Changed |
// | Delay      | Reachable  | Solicited override confirmation            | Update LinkAddr | Changed |
// | Delay      | Stale      | Probe or confirmation w/ different address |                 | Changed |
// | Delay      | Probe      | Delay timer expired                        | Send probe      | Changed |
// | Probe      | Reachable  | Solicited override confirmation            | Update LinkAddr | Changed |
// | Probe      | Reachable  | Solicited confirmation w/ same address     | Notify wakers   | Changed |
// | Probe      | Stale      | Probe or confirmation w/ different address |                 | Changed |
// | Probe      | Probe      | Retransmit timer expired                   | Send probe      | Changed |
// | Probe      | Failed     | Max probes sent without reply              | Notify wakers   | Removed |
// | Failed     |            | Unreachability timer expired               | Delete entry    |         |

type testEntryEventType uint8

const (
	entryTestAdded testEntryEventType = iota
	entryTestChanged
	entryTestRemoved
)

func (t testEntryEventType) String() string {
	switch t {
	case entryTestAdded:
		return "add"
	case entryTestChanged:
		return "change"
	case entryTestRemoved:
		return "remove"
	default:
		return fmt.Sprintf("unknown (%d)", t)
	}
}

// Fields are exported for use with cmp.Diff.
type testEntryEventInfo struct {
	EventType testEntryEventType
	NICID     tcpip.NICID
	Addr      tcpip.Address
	LinkAddr  tcpip.LinkAddress
	State     NeighborState
	UpdatedAt time.Time
}

func (e testEntryEventInfo) String() string {
	return fmt.Sprintf("%s event for NIC #%d, addr=%q, linkAddr=%q, state=%q", e.EventType, e.NICID, e.Addr, e.LinkAddr, e.State)
}

// testNUDDispatcher implements NUDDispatcher to validate the dispatching of
// events upon certain NUD state machine events.
type testNUDDispatcher struct {
	mu struct {
		sync.Mutex

		events []testEntryEventInfo
	}
}

var _ NUDDispatcher = (*testNUDDispatcher)(nil)

func (d *testNUDDispatcher) queueEvent(e testEntryEventInfo) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mu.events = append(d.mu.events, e)
}

func (d *testNUDDispatcher) OnNeighborAdded(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState, updatedAt time.Time) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestAdded,
		NICID:     nicID,
		Addr:      addr,
		LinkAddr:  linkAddr,
		State:     state,
		UpdatedAt: updatedAt,
	})
}

func (d *testNUDDispatcher) OnNeighborChanged(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState, updatedAt time.Time) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestChanged,
		NICID:     nicID,
		Addr:      addr,
		LinkAddr:  linkAddr,
		State:     state,
		UpdatedAt: updatedAt,
	})
}

func (d *testNUDDispatcher) OnNeighborRemoved(nicID tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress, state NeighborState, updatedAt time.Time) {
	d.queueEvent(testEntryEventInfo{
		EventType: entryTestRemoved,
		NICID:     nicID,
		Addr:      addr,
		LinkAddr:  linkAddr,
		State:     state,
		UpdatedAt: updatedAt,
	})
}

type entryTestLinkResolver struct {
	mu struct {
		sync.Mutex

		probes []entryTestProbeInfo
	}
}

var _ LinkAddressResolver = (*entryTestLinkResolver)(nil)

type entryTestProbeInfo struct {
	RemoteAddress     tcpip.Address
	RemoteLinkAddress tcpip.LinkAddress
	LocalAddress      tcpip.Address
}

func (p entryTestProbeInfo) String() string {
	return fmt.Sprintf("probe with RemoteAddress=%q, RemoteLinkAddress=%q, LocalAddress=%q", p.RemoteAddress, p.RemoteLinkAddress, p.LocalAddress)
}

// LinkAddressRequest sends a request for the LinkAddress of addr. Broadcasts
// to the local network if linkAddr is the zero value.
func (r *entryTestLinkResolver) LinkAddressRequest(addr, localAddr tcpip.Address, linkAddr tcpip.LinkAddress, linkEP LinkEndpoint) *tcpip.Error {
	p := entryTestProbeInfo{
		RemoteAddress:     addr,
		RemoteLinkAddress: linkAddr,
		LocalAddress:      localAddr,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mu.probes = append(r.mu.probes, p)
	return nil
}

// ResolveStaticAddress attempts to resolve address without sending requests.
// It either resolves the name immediately or returns the empty LinkAddress.
func (r *entryTestLinkResolver) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	return "", false
}

// LinkAddressProtocol returns the network protocol of the addresses this
// resolver can resolve.
func (r *entryTestLinkResolver) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return entryTestNetNumber
}

type workItem struct {
	id        uint64 // used for finding the item during cancellation
	locker    sync.Locker
	executeAt time.Time
	fn        func()
}

// fakeClock allows manipulation of work scheduling.
type fakeClock struct {
	mu struct {
		sync.Mutex

		now       time.Time
		work      []workItem
		idCounter uint64
	}
}

var _ tcpip.Clock = (*fakeClock)(nil)

func (c *fakeClock) NowNanoseconds() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mu.now.UnixNano()
}

func (c *fakeClock) NowMonotonic() int64 {
	return c.NowNanoseconds()
}

func (c *fakeClock) AfterFunc(l sync.Locker, d time.Duration, f func()) context.CancelFunc {
	if d == infiniteDuration {
		return func() {}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	id := c.mu.idCounter
	c.mu.idCounter++
	c.mu.work = append(c.mu.work, workItem{
		id:        id,
		locker:    l,
		executeAt: c.mu.now.Add(d),
		fn:        f,
	})

	sort.Slice(c.mu.work, func(i, j int) bool {
		return c.mu.work[i].executeAt.Before(c.mu.work[j].executeAt)
	})

	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for i, item := range c.mu.work {
			if item.id == id {
				c.mu.work = append(c.mu.work[:i], c.mu.work[i+1:]...)
				return
			}
		}
	}
}

// nextWorkItems consumes and returns the next batch of work items with the
// same scheduled execution time.
func (c *fakeClock) nextWorkItems() []workItem {
	c.mu.Lock()
	defer c.mu.Unlock()

	var items []workItem
	var executeAt time.Time

	for i, item := range c.mu.work {
		if i == 0 {
			executeAt = item.executeAt
		} else if item.executeAt != executeAt {
			break
		}
		items = append(items, item)
	}

	if len(items) != 0 {
		c.mu.work = c.mu.work[len(items):]
		c.mu.now = executeAt
	}

	return items
}

// advance executes the next batch of work items with the same scheduled
// execution time. Will block until the entire batch is done executing, however
// each work item will run concurrently with each other. Returns false if there
// is no work left.
func (c *fakeClock) advance() bool {
	items := c.nextWorkItems()
	if len(items) == 0 {
		return false
	}

	var wg sync.WaitGroup
	for _, item := range items {
		item := item // capture range variable
		wg.Add(1)
		go func() {
			if item.locker != nil {
				item.locker.Lock()
				defer item.locker.Unlock()
			}
			item.fn()
			wg.Done()
		}()
	}
	wg.Wait()

	return true
}

// advanceAll executes all work items.
func (c *fakeClock) advanceAll() {
	for c.advance() {
	}
}

func entryTestSetup(c NUDConfigurations) (*neighborEntry, *testNUDDispatcher, *entryTestLinkResolver, *fakeClock) {
	clock := fakeClock{}
	disp := testNUDDispatcher{}
	nic := NIC{
		id:     entryTestNICID,
		linkEP: nil, // entryTestLinkResolver doesn't use a LinkEndpoint
		stack: &Stack{
			clock:   &clock,
			nudDisp: &disp,
		},
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	nudState := NewNUDState(c, rng)
	linkRes := entryTestLinkResolver{}
	entry := newNeighborEntry(&nic, entryTestAddr1, entryTestAddr2, nudState, &linkRes)

	// Stub out ndpState to verify modification of default routers.
	nic.mu.ndp = ndpState{
		nic:            &nic,
		defaultRouters: make(map[tcpip.Address]defaultRouterState),
	}

	// Stub out the neighbor cache to verify deletion from the cache.
	nic.neigh = &neighborCache{
		nic:   &nic,
		state: nudState,
	}
	nic.neigh.mu.cache = make(map[tcpip.Address]*neighborEntry, neighborCacheSize)
	nic.neigh.mu.cache[entryTestAddr1] = entry

	return entry, &disp, &linkRes, &clock
}

// TestEntryInitiallyUnknown verifies that the state of a newly created
// neighborEntry is Unknown.
func TestEntryInitiallyUnknown(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Unknown; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	// No probes should have been sent.
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, []entryTestProbeInfo(nil)); diff != "" {
		t.Fatalf("unexpectedly sent probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryUnknownToUnknownWhenConfirmationWithUnknownAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Unknown; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	// No probes should have been sent.
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, []entryTestProbeInfo(nil)); diff != "" {
		t.Fatalf("unexpectedly sent probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	// No events should have been dispatched.
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, []testEntryEventInfo(nil)); diff != "" {
		t.Errorf("unexpectedly got events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryUnknownToIncomplete(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Fatalf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryUnknownToStale(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handleProbeLocked(entryTestLinkAddr1)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	// No probes should have been sent.
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, []entryTestProbeInfo(nil)); diff != "" {
		t.Fatalf("unexpectedly sent probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryIncompleteToIncompleteDoesNotChangeUpdatedAt(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	updatedAt := e.mu.neigh.UpdatedAt
	e.mu.Unlock()

	clock.advance()

	// Wait for the first two probes then verify that UpdatedAt did not change.
	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.probes = nil
	linkRes.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.UpdatedAt, updatedAt; got != want {
		t.Errorf("e.mu.neigh.UpdatedAt=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advance()

	// Wait for the transition to Failed then verify that UpdatedAt changed.
	wantProbes = []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	clock.advance()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, notWant := e.mu.neigh.UpdatedAt, updatedAt; got == notWant {
		t.Errorf("expected e.mu.neigh.UpdatedAt to change, got=%q", got)
	}
	e.mu.Unlock()
}

func TestEntryIncompleteToReachable(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.BaseReachableTime = infiniteDuration // stay in reachable
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

// TestEntryAddsAndClearsWakers verifies that wakers are added when
// addWakerLocked is called and cleared when address resolution finishes. In
// this case, address resolution will finish when transitioning from Incomplete
// to Reachable.
func TestEntryAddsAndClearsWakers(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.BaseReachableTime = infiniteDuration // stay in reachable
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	w := sleep.Waker{}
	s := sleep.Sleeper{}
	s.AddWaker(&w, 123)
	defer s.Done()

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got := e.mu.wakers; got != nil {
		t.Errorf("got e.mu.wakers=%v, want=nil", got)
	}
	e.addWakerLocked(&w)
	if got, want := w.IsAsserted(), false; got != want {
		t.Errorf("waker.IsAsserted()=%t, want=%t", got, want)
	}
	if e.mu.wakers == nil {
		t.Error("expected e.mu.wakers to be non-nil")
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if e.mu.wakers != nil {
		t.Errorf("e.mu.wakers=%v, want=nil", e.mu.wakers)
	}
	if got, want := w.IsAsserted(), true; got != want {
		t.Errorf("waker.IsAsserted()=%t, want=%t", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryIncompleteToReachableWithRouterFlag(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.BaseReachableTime = infiniteDuration // stay in reachable
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  true,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.isRouter, true; got != want {
		t.Errorf("e.mu.isRouter=%t, want=%t", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryIncompleteToStale(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.BaseReachableTime = infiniteDuration // stay in reachable
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryIncompleteToFailed(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	c.UnreachableTime = infiniteDuration // don't transition out of Failed
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Incomplete; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		// The Incomplete-to-Incomplete state transition is tested here by
		// verifying that 3 reachability probes were sent.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Failed; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

type testLocker struct{}

var _ sync.Locker = (*testLocker)(nil)

func (*testLocker) Lock()   {}
func (*testLocker) Unlock() {}

func TestEntryStaysReachableWhenConfirmationWithRouterFlag(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.BaseReachableTime = infiniteDuration // don't timeout to Stale
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  true,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.isRouter, true; got != want {
		t.Errorf("e.mu.isRouter=%t, want=%t", got, want)
	}
	e.nic.mu.ndp.defaultRouters[entryTestAddr1] = defaultRouterState{
		invalidationTimer: tcpip.NewCancellableTimer(&testLocker{}, func() {}),
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.isRouter, false; got != want {
		t.Errorf("e.mu.isRouter=%t, want=%t", got, want)
	}
	if _, ok := e.nic.mu.ndp.defaultRouters[entryTestAddr1]; ok {
		t.Errorf("unexpected defaultRouter for %s", entryTestAddr1)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryStaysReachableWhenProbeWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.BaseReachableTime = infiniteDuration // stay in reachable
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr1)
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryReachableToStaleWhenTimeout(t *testing.T) {
	c := DefaultNUDConfigurations()
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryReachableToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration
	c.BaseReachableTime = infiniteDuration // disable Reachable timer
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryReachableToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration
	c.BaseReachableTime = infiniteDuration // disable Reachable timer
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryReachableToStaleWhenConfirmationWithDifferentAddressAndOverride(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration
	c.BaseReachableTime = infiniteDuration // disable Reachable timer
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryStaysStaleWhenProbeWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr1)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.BaseReachableTime = infiniteDuration // stay in reachable
	c.MinRandomFactor = 1
	c.MaxRandomFactor = 1
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Reachable,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToStaleWhenOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToStaleWhenProbeUpdateAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaleToDelay(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration     // only send one probe
	c.DelayFirstProbeTime = infiniteDuration // only send one probe
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToReachableWhenUpperLevelConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.DelayFirstProbeTime = infiniteDuration // stay in Delay
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleUpperLevelConfirmationLocked()
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		// The entry will transition to Stale since the clock advances all the way
		// until a steady state is reached.
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 1
	c.DelayFirstProbeTime = infiniteDuration // stay in Delay
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Reachable,
		},
		// The entry will transition to Stale since the clock advances all the way
		// until a steady state is reached.
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryStaysDelayWhenOverrideConfirmationWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration     // only send one probe
	c.DelayFirstProbeTime = infiniteDuration // stay in Delay
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration     // only send one probe
	c.DelayFirstProbeTime = infiniteDuration // stay in Delay
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration     // only send one probe
	c.DelayFirstProbeTime = infiniteDuration // stay in Delay
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryDelayToProbe(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	if got, want := e.mu.neigh.State, Delay; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryProbeToStaleWhenProbeWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleProbeLocked(entryTestLinkAddr2)
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryProbeToStaleWhenConfirmationWithDifferentAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Stale; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryStaysProbeWhenOverrideConfirmationWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr1; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryProbeToReachableWhenSolicitedOverrideConfirmation(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe and don't timeout
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr2, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  true,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	if got, want := e.mu.neigh.LinkAddr, entryTestLinkAddr2; got != want {
		t.Errorf("e.mu.neigh.LinkAddr=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Reachable,
		},
		// The entry will transition to Stale since the clock advances all the way
		// until a steady state is reached.
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr2,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryProbeToReachableWhenSolicitedConfirmationWithSameAddress(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.RetransmitTimer = infiniteDuration // only send one probe and don't timeout
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The second probe is caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Probe; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: true,
		Override:  false,
		IsRouter:  false,
	})
	if got, want := e.mu.neigh.State, Reachable; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()

	clock.advanceAll()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Reachable,
		},
		// The entry will transition to Stale since the clock advances all the way
		// until a steady state is reached.
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()
}

func TestEntryProbeToFailed(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	c.MaxUnicastProbes = 3
	c.UnreachableTime = infiniteDuration // don't transition out of Failed
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The next three probe are caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	e.mu.Lock()
	if got, want := e.mu.neigh.State, Failed; got != want {
		t.Errorf("e.mu.neigh.State=%q, want=%q", got, want)
	}
	e.mu.Unlock()
}

func TestEntryFailedGetsDeleted(t *testing.T) {
	c := DefaultNUDConfigurations()
	c.MaxMulticastProbes = 3
	c.MaxUnicastProbes = 3
	e, nudDisp, linkRes, clock := entryTestSetup(c)

	// Verify the cache contains the entry.
	if _, ok := e.nic.neigh.mu.cache[entryTestAddr1]; !ok {
		t.Errorf("expected entry %q to exist in the neighbor cache", entryTestAddr1)
	}

	e.mu.Lock()
	e.handlePacketQueuedLocked()
	e.handleConfirmationLocked(entryTestLinkAddr1, ReachabilityConfirmationFlags{
		Solicited: false,
		Override:  false,
		IsRouter:  false,
	})
	e.handlePacketQueuedLocked()
	e.mu.Unlock()

	clock.advanceAll()

	wantProbes := []entryTestProbeInfo{
		// The first probe is caused by the Unknown-to-Incomplete transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: tcpip.LinkAddress(""),
			LocalAddress:      entryTestAddr2,
		},
		// The next three probe are caused by the Delay-to-Probe transition.
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
		{
			RemoteAddress:     entryTestAddr1,
			RemoteLinkAddress: entryTestLinkAddr1,
			LocalAddress:      entryTestAddr2,
		},
	}
	linkRes.mu.Lock()
	if diff := cmp.Diff(linkRes.mu.probes, wantProbes); diff != "" {
		t.Fatalf("sent invalid probes (-got, +want):\n%s", diff)
	}
	linkRes.mu.Unlock()

	wantEvents := []testEntryEventInfo{
		{
			EventType: entryTestAdded,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  tcpip.LinkAddress(""),
			State:     Incomplete,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Stale,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Delay,
		},
		{
			EventType: entryTestChanged,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
		{
			EventType: entryTestRemoved,
			NICID:     entryTestNICID,
			Addr:      entryTestAddr1,
			LinkAddr:  entryTestLinkAddr1,
			State:     Probe,
		},
	}
	nudDisp.mu.Lock()
	if diff := cmp.Diff(nudDisp.mu.events, wantEvents, eventDiffOpts); diff != "" {
		t.Errorf("got invalid events (-got, +want):\n%s", diff)
	}
	nudDisp.mu.Unlock()

	// Verify the cache no longer contains the entry.
	if _, ok := e.nic.neigh.mu.cache[entryTestAddr1]; ok {
		t.Errorf("entry %q should have been deleted from the neighbor cache", entryTestAddr1)
	}
}
