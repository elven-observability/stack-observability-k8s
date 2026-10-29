// Copyright Elven Observability contributors. SPDX-License-Identifier: Apache-2.0
// Collect license texts from checksum-verified modules; no network or secrets.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type module struct {
	Path, Version, Dir string
	Replace            *module
}
type notice struct {
	Module, Version, File, SHA256 string
}

func die(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func copyNotice(dir, relative, root, path, version string, entries *[]notice) error {
	data, err := os.ReadFile(filepath.Join(dir, relative))
	if err != nil {
		return err
	}
	name := strings.NewReplacer("/", "__", "\\", "__", ":", "_").Replace(path + "@" + version)
	destination := filepath.Join(root, name, relative)
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(destination, data, 0444); err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	*entries = append(*entries, notice{path, version, relative, hex.EncodeToString(digest[:])})
	return nil
}
func main() {
	if len(os.Args) != 2 {
		die(fmt.Errorf("usage: license-bundle OUTPUT < go-modules.json"))
	}
	root := os.Args[1]
	decoder := json.NewDecoder(os.Stdin)
	var entries []notice
	count := 0
	for {
		var item module
		if err := decoder.Decode(&item); err == io.EOF {
			break
		} else if err != nil {
			die(err)
		}
		if item.Replace != nil {
			item = *item.Replace
		}
		if item.Dir == "" {
			continue
		} // unneeded/lazy modules have no compiled source
		count++
		err := filepath.WalkDir(item.Dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			name := strings.ToUpper(entry.Name())
			wanted := strings.HasPrefix(name, "LICENSE") || strings.HasPrefix(name, "LICENCE") || strings.HasPrefix(name, "NOTICE") || strings.HasPrefix(name, "COPYING") || name == "COPYRIGHT"
			if !wanted || strings.HasSuffix(strings.ToLower(name), ".go") {
				return nil
			}
			relative, err := filepath.Rel(item.Dir, path)
			if err != nil {
				return err
			}
			return copyNotice(item.Dir, relative, root, item.Path, item.Version, &entries)
		})
		if err != nil {
			die(err)
		}
	}
	if count < 10 || len(entries) < 10 {
		die(fmt.Errorf("incomplete Go module/license inventory: %d modules, %d notices", count, len(entries)))
	}
	if err := copyNotice(runtime.GOROOT(), "LICENSE", root, "go-stdlib", runtime.Version(), &entries); err != nil {
		die(err)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Module == entries[j].Module {
			return entries[i].File < entries[j].File
		}
		return entries[i].Module < entries[j].Module
	})
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		die(err)
	}
	if err := os.WriteFile(filepath.Join(root, "MANIFEST.json"), append(data, '\n'), 0444); err != nil {
		die(err)
	}
	fmt.Fprintf(os.Stderr, "Bundled %d license/notice texts from %d verified modules and Go stdlib\n", len(entries), count)
}
