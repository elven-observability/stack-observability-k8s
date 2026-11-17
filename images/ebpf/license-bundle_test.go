package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func fixtures(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	vendor := filepath.Join(root, "vendor")
	for i := 0; i < 10; i++ {
		path := filepath.Join(vendor, fmt.Sprintf("example.org/dependency-%d/LICENSE", i))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("synthetic upstream notice"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	goLicense := filepath.Join(root, "GO-LICENSE")
	if err := os.WriteFile(goLicense, []byte("synthetic Go license"), 0644); err != nil {
		t.Fatal(err)
	}
	return vendor, goLicense, filepath.Join(root, "output")
}

func TestBundlePreservesAndHashesEveryNotice(t *testing.T) {
	vendor, goLicense, output := fixtures(t)
	if err := bundle(vendor, goLicense, output); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(output, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var records []notice
	if err := json.Unmarshal(raw, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 11 {
		t.Fatalf("notices=%d", len(records))
	}
	for _, record := range records {
		raw, err := os.ReadFile(filepath.Join(output, record.File))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		if hex.EncodeToString(hash[:]) != record.SHA256 {
			t.Fatalf("notice changed: %s", record.File)
		}
	}
}

func TestBundleRejectsSymlinkNotice(t *testing.T) {
	vendor, goLicense, output := fixtures(t)
	if err := os.Symlink(goLicense, filepath.Join(vendor, "NOTICE")); err != nil {
		t.Fatal(err)
	}
	if err := bundle(vendor, goLicense, output); err == nil {
		t.Fatal("symlink was adopted")
	}
}

func TestBundleRejectsAnEmptyVendorTree(t *testing.T) {
	vendor := t.TempDir()
	if err := bundle(vendor, filepath.Join(vendor, "absent"), filepath.Join(t.TempDir(), "output")); err == nil {
		t.Fatal("incomplete bundle accepted")
	}
}
