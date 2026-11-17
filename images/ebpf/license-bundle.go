// Preserve notices from the verified vendor tree without claiming upstream authorship.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type notice struct{ File, SHA256 string }

func bundle(vendor, goLicense, output string) error {
	var records []notice
	copyNotice := func(source, relative string) error {
		info, err := os.Lstat(source)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 4<<20 {
			return fmt.Errorf("invalid notice source: %s", relative)
		}
		raw, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		destination := filepath.Join(output, relative)
		if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(destination, raw, 0644); err != nil {
			return err
		}
		hash := sha256.Sum256(raw)
		records = append(records, notice{File: filepath.ToSlash(relative), SHA256: hex.EncodeToString(hash[:])})
		return nil
	}
	err := filepath.WalkDir(vendor, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		name := strings.ToUpper(entry.Name())
		for _, prefix := range []string{"LICENSE", "LICENCE", "NOTICE", "COPYING", "COPYRIGHT"} {
			if strings.HasPrefix(name, prefix) {
				relative, err := filepath.Rel(vendor, path)
				if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
					return fmt.Errorf("notice escapes source tree")
				}
				return copyNotice(path, relative)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(records) < 10 {
		return fmt.Errorf("vendor notice bundle is incomplete")
	}
	if err := copyNotice(goLicense, "go-stdlib/LICENSE"); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, "MANIFEST.json"), append(raw, '\n'), 0644)
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: license-bundle VENDOR GO-LICENSE OUTPUT")
		os.Exit(2)
	}
	if err := bundle(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
