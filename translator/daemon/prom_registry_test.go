package daemon

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// registerLikeStandaloneConnector mimics daemon.NewStandaloneConnector, which
// registers a fixed-name collector with prometheus.MustRegister on every call.
func registerLikeStandaloneConnector() (int, error) {
	prometheus.MustRegister(prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "trustengine_db_queries_total", Help: "test"},
		[]string{"driver", "operation", "result"},
	))
	return 1, nil
}

// Regression test: the second connector in the same process (tunnel restart
// on Android) panicked with "duplicate metrics collector registration
// attempted".
func TestWithIsolatedPromRegistryAllowsRepeatedRegistration(t *testing.T) {
	defaultBefore := prometheus.DefaultRegisterer

	for i := 0; i < 3; i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("call %d panicked: %v", i+1, r)
				}
			}()
			if _, err := withIsolatedPromRegistry(registerLikeStandaloneConnector); err != nil {
				t.Fatalf("call %d: %v", i+1, err)
			}
		}()
	}

	if prometheus.DefaultRegisterer != defaultBefore {
		t.Fatal("DefaultRegisterer was not restored")
	}
}

// Documents the original failure mode without isolation.
func TestRepeatedRegistrationWithoutIsolationPanics(t *testing.T) {
	prev := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	defer func() { prometheus.DefaultRegisterer = prev }()

	_, _ = registerLikeStandaloneConnector()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	_, _ = registerLikeStandaloneConnector()
}

func TestSciondRetrieverCloseNilSafe(t *testing.T) {
	var r *SciondRetriever
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := (&SciondRetriever{}).Close(); err != nil {
		t.Fatal(err)
	}
}
