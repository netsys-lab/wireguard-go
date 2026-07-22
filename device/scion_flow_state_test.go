package device

import (
	"sync"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/flow"
)

func TestRememberAndGetSCIONEgress(t *testing.T) {
	d := &Device{
		scionFlowMu:     sync.RWMutex{},
		scionFlowStates: make(map[flow.ID]SCIONEgressState),
	}

	srcIA := addr.MustIAFrom(1, 0xff0000000110)
	dstIA := addr.MustIAFrom(1, 0xff0000000112)

	d.rememberSCIONEgress(1, srcIA, dstIA)

	state, ok := d.getSCIONEgress(1)
	if !ok {
		t.Fatal("expected to find SCION egress state")
	}
	if state.FlowID != 1 {
		t.Fatalf("expected flow ID 1, got %d", state.FlowID)
	}
	if state.SrcIA != srcIA {
		t.Fatalf("expected srcIA %s, got %s", srcIA, state.SrcIA)
	}
	if state.DstIA != dstIA {
		t.Fatalf("expected dstIA %s, got %s", dstIA, state.DstIA)
	}
}

func TestGetSCIONEgressUnknown(t *testing.T) {
	d := &Device{
		scionFlowMu:     sync.RWMutex{},
		scionFlowStates: make(map[flow.ID]SCIONEgressState),
	}

	_, ok := d.getSCIONEgress(999)
	if ok {
		t.Fatal("expected false for unknown flow ID")
	}
}

func TestRememberSCIONEgressIdempotent(t *testing.T) {
	d := &Device{
		scionFlowMu:     sync.RWMutex{},
		scionFlowStates: make(map[flow.ID]SCIONEgressState),
	}

	srcIA := addr.MustIAFrom(1, 0xff0000000110)
	dstIA := addr.MustIAFrom(1, 0xff0000000112)

	d.rememberSCIONEgress(1, srcIA, dstIA)
	d.rememberSCIONEgress(1, srcIA, dstIA)

	state, ok := d.getSCIONEgress(1)
	if !ok {
		t.Fatal("expected to find SCION egress state")
	}
	if state.SrcIA != srcIA {
		t.Fatalf("expected srcIA %s, got %s", srcIA, state.SrcIA)
	}
}

func TestRememberSCIONEgressPreservesFirstOnConflict(t *testing.T) {
	d := &Device{
		scionFlowMu:     sync.RWMutex{},
		scionFlowStates: make(map[flow.ID]SCIONEgressState),
	}

	srcIA1 := addr.MustIAFrom(1, 0xff0000000110)
	dstIA1 := addr.MustIAFrom(1, 0xff0000000112)
	srcIA2 := addr.MustIAFrom(1, 0xff0000000111)
	dstIA2 := addr.MustIAFrom(1, 0xff0000000113)

	d.rememberSCIONEgress(1, srcIA1, dstIA1)
	d.rememberSCIONEgress(1, srcIA2, dstIA2)

	state, _ := d.getSCIONEgress(1)
	if state.SrcIA != srcIA1 || state.DstIA != dstIA1 {
		t.Fatalf("expected first IA pair %s->%s, got %s->%s", srcIA1, dstIA1, state.SrcIA, state.DstIA)
	}
}

func TestRememberSCIONEgressConcurrent(t *testing.T) {
	d := &Device{
		scionFlowMu:     sync.RWMutex{},
		scionFlowStates: make(map[flow.ID]SCIONEgressState),
	}

	srcIA := addr.MustIAFrom(1, 0xff0000000110)
	dstIA := addr.MustIAFrom(1, 0xff0000000112)

	var wg sync.WaitGroup
	for i := flow.ID(0); i < 100; i++ {
		wg.Add(1)
		go func(id flow.ID) {
			defer wg.Done()
			d.rememberSCIONEgress(id, srcIA, dstIA)
		}(i)
	}
	wg.Wait()

	for i := flow.ID(0); i < 100; i++ {
		state, ok := d.getSCIONEgress(i)
		if !ok {
			t.Fatalf("expected flow %d to exist", i)
		}
		if state.SrcIA != srcIA || state.DstIA != dstIA {
			t.Fatalf("flow %d: expected %s->%s, got %s->%s", i, srcIA, dstIA, state.SrcIA, state.DstIA)
		}
	}
}

func TestGetSCIONEgressConcurrentSafe(t *testing.T) {
	d := &Device{
		scionFlowMu:     sync.RWMutex{},
		scionFlowStates: make(map[flow.ID]SCIONEgressState),
	}

	srcIA := addr.MustIAFrom(1, 0xff0000000110)
	dstIA := addr.MustIAFrom(1, 0xff0000000112)

	d.rememberSCIONEgress(1, srcIA, dstIA)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok := d.getSCIONEgress(1)
			if !ok {
				t.Error("expected flow 1 to exist")
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.rememberSCIONEgress(2, srcIA, dstIA)
		}()
	}
	wg.Wait()
}
