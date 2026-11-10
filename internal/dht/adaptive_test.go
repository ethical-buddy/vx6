package dht

import "testing"

func TestAdaptiveLookupParamsScaleWithFailureEWMA(t *testing.T) {
	s := NewServer("self")
	alpha, budget := s.adaptiveLookupParams()
	if alpha != defaultLookupAlpha || budget != defaultLookupQueryBudget {
		t.Fatalf("unexpected defaults alpha=%d budget=%d", alpha, budget)
	}

	s.lookupEWMA = 0.40
	alpha, budget = s.adaptiveLookupParams()
	if alpha <= defaultLookupAlpha {
		t.Fatalf("expected alpha to increase under churn, got %d", alpha)
	}
	if budget != defaultLookupRounds*defaultLookupParallelism {
		t.Fatalf("adaptive budget=%d; want the 80-query protocol ceiling", budget)
	}
}

func TestAdaptiveReplicationTargetScaleWithFailureEWMA(t *testing.T) {
	s := NewServer("self")
	if got := s.adaptiveReplicationTarget(); got != defaultReplicationFactor {
		t.Fatalf("unexpected default replication target %d", got)
	}
	s.lookupEWMA = 0.36
	if got := s.adaptiveReplicationTarget(); got <= defaultReplicationFactor {
		t.Fatalf("expected replication target increase under churn, got %d", got)
	}
}

func TestNoteLookupResultUpdatesEWMA(t *testing.T) {
	s := NewServer("self")
	s.noteLookupResult(false)
	if s.lookupEWMA <= 0 {
		t.Fatalf("expected ewma > 0 after failure, got %f", s.lookupEWMA)
	}
	before := s.lookupEWMA
	s.noteLookupResult(true)
	if s.lookupEWMA >= before {
		t.Fatalf("expected ewma to decay on success, before=%f after=%f", before, s.lookupEWMA)
	}
}
