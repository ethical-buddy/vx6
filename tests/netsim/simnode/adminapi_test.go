// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"strings"
	"testing"

	"github.com/vx6/vx6/internal/dht"
)

func TestNodeLookupTargetUsesSeparateIdentityAndNameCoordinates(t *testing.T) {
	id := "vx6_" + strings.Repeat("a", 64)
	key, expected, reported, err := nodeLookupTarget("id", id)
	if err != nil || key != "node/id/"+id || expected != id || reported != id {
		t.Fatalf("ID lookup target = %q, %q, %q, err=%v", key, expected, reported, err)
	}

	key, expected, reported, err = nodeLookupTarget("name", "amber-fox")
	wantHash := dht.NodeNameHash("AMBER-FOX")
	if err != nil || key != "node/name/"+wantHash || expected != "" || reported != wantHash {
		t.Fatalf("name lookup target = %q, %q, %q, err=%v", key, expected, reported, err)
	}
	if strings.Contains(key, "AMBER-FOX") || strings.Contains(key, "amber-fox") {
		t.Fatalf("clear node name leaked into DHT target %q", key)
	}
}

func TestNodeLookupTargetRejectsNonCanonicalIdentityAndNames(t *testing.T) {
	for _, id := range []string{
		"vx6_" + strings.Repeat("A", 64),
		"vx6_" + strings.Repeat("a", 63),
		"other_" + strings.Repeat("a", 64),
	} {
		if _, _, _, err := nodeLookupTarget("id", id); err == nil {
			t.Fatalf("invalid identity target accepted: %q", id)
		}
	}
	for _, name := range []string{"", "A", "TOO-MANY-CHARS-NAME"} {
		if _, _, _, err := nodeLookupTarget("name", name); err == nil {
			t.Fatalf("invalid name target accepted: %q", name)
		}
	}
	if _, _, _, err := nodeLookupTarget("service", "AMBER-FOX"); err == nil {
		t.Fatal("unsupported lookup type accepted")
	}
}
