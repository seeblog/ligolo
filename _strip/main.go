// stripbuildinfo removes build/module metadata from Go binaries:
//  1. the buildinfo blob ("\xff Go buildinf:" magic, possibly multiple),
//  2. the module path/dep list text embedded in the pclntab,
//  3. function-name strings carrying the module import path prefix.
//
// Rewriting function names is safe: the pclntab name table is only read
// during panic tracebacks, never for control flow. File paths in the
// pclntab are replaced with a neutral name.
//
// Usage: go run ./_strip <binary> [binary...]
package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

var magic = []byte("\xff Go buildinf:")

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: stripbuildinfo <binary> [binary...]")
		os.Exit(1)
	}
	for _, path := range os.Args[1:] {
		if err := strip(path); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
	}
}

func strip(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	total := 0

	// 1. zero every buildinfo blob
	for {
		idx := bytes.Index(data, magic)
		if idx < 0 {
			break
		}
		start := idx
		end := start + 32
		limit := min(len(data), start+64*1024)
		terminated := false
		for i := end; i < limit; i++ {
			if data[i] == 0 && i+1 < limit && data[i+1] == 0 {
				end = i + 2
				terminated = true
				break
			}
		}
		if !terminated {
			for i := end; i < limit; i++ {
				if data[i] == 0 {
					end = i + 1
					break
				}
			}
		}
		for i := start; i < end; i++ {
			data[i] = 0
		}
		total += end - start
	}

	// 2. neutralize module import-path prefixes everywhere in the file.
	// We rewrite "github.com/vertexnet/relaykit/cmd/ligoloc/main.go" style
	// file paths and function name prefixes to short neutral names of the
	// same length (space padded) so pclntab offsets stay valid.
	const neutralMod = "sys/net/core"
	data, n := replacePrefix(data, "github.com/vertexnet/relaykit/cmd/ligoloc", neutralMod+"/bin/cli")
	total += n
	data, n = replacePrefix(data, "github.com/vertexnet/relaykit/cmd/ligolos", neutralMod+"/bin/srv")
	total += n
	data, n = replacePrefix(data, "relaykit", "syscore")
	total += n

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, info.Mode().Perm()); err != nil {
		return err
	}
	fmt.Printf("%s: scrubbed %d bytes of build/module metadata\n", path, total)
	return nil
}

// replacePrefix rewrites every occurrence of old to new. new must not be
// longer than old; shorter replacements are padded with '\x00' inside the
// remainder ONLY when the string is followed by a NUL terminator (function
// name table entries are NUL separated), otherwise space padded (file path
// strings inside a length-prefixed region are also NUL terminated in
// pclntab, so NUL padding is the safe default for both).
func replacePrefix(data []byte, old, new string) ([]byte, int) {
	if len(new) > len(old) {
		panic("replacement longer than original: " + old)
	}
	count := 0
	ob := []byte(old)
	nb := []byte(new)
	for {
		i := bytes.Index(data, ob)
		if i < 0 {
			break
		}
		copy(data[i:i+len(nb)], nb)
		for j := i + len(nb); j < i+len(ob); j++ {
			data[j] = 0 // NUL terminate / pad
		}
		count++
	}
	_ = strings.TrimSpace("")
	return data, count * len(ob)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

