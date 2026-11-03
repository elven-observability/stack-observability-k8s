// Copyright Elven Observability contributors. SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalSourcePreservesCanonicalElvenIdentity(t *testing.T) {
	const path = "github.com/elven-observability/stack-observability-k8s/processor/elvenprivacyprocessor"
	got, origin, err := moduleIdentity(module{Path: path, Version: "v0.0.0", Replace: &module{Path: "/src/elvenprivacyprocessor", Dir: "/src/elvenprivacyprocessor"}})
	if err != nil || got.Path != path || got.Version != "v0.0.0" || got.Dir != "/src/elvenprivacyprocessor" || origin != "elven-source" {
		t.Fatalf("local identity lost: module=%+v origin=%q err=%v", got, origin, err)
	}
}

func TestPatchedUpstreamUsesVerifiedReplacementIdentity(t *testing.T) {
	got, origin, err := moduleIdentity(module{Path: "example.org/upstream", Version: "v1.0.0", Replace: &module{Path: "example.org/upstream", Version: "v1.0.1", Dir: "/go/pkg/mod/upstream"}})
	if err != nil || got.Version != "v1.0.1" || got.Dir != "/go/pkg/mod/upstream" || origin != "upstream-module" {
		t.Fatalf("replacement identity lost: module=%+v origin=%q err=%v", got, origin, err)
	}
}

func TestUnknownOrMissingLocalReplacementsAreRejected(t *testing.T) {
	for _, item := range []module{
		{Path: "example.org/unverified", Replace: &module{Path: "/src/external", Dir: "/src/external"}},
		{Path: "github.com/elven-observability/stack-observability-k8s/processor/elvenprivacyprocessor", Replace: &module{Path: "/src/missing"}},
		{Path: "example.org/unexpected-main", Main: true},
	} {
		if _, _, err := moduleIdentity(item); err == nil {
			t.Fatalf("accepted unverified local source: %+v", item)
		}
	}
}

func TestNoticeRetainsExactBytesAndExplicitOrigin(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()
	payload := []byte("Synthetic Elven license fixture\n\n")
	if err := os.WriteFile(filepath.Join(source, "LICENSE"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	var entries []notice
	if err := copyNotice(source, "LICENSE", destination, "elven/example", "v0.0.0", "elven-source", &entries); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if len(entries) != 1 || entries[0].Origin != "elven-source" || entries[0].SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("incorrect manifest: %+v", entries)
	}
	got, err := os.ReadFile(filepath.Join(destination, "elven__example@v0.0.0", "LICENSE"))
	if err != nil || string(got) != string(payload) {
		t.Fatalf("license bytes modified: %q, %v", got, err)
	}
}
