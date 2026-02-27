// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-dumpsections dumps all executable ELF sections (SHT_PROGBITS + SHF_EXECINSTR)
// using two methods:
//   1. Go's debug/elf package (same as pkg/cover/backend uses)
//   2. External llvm-readelf/readelf command (ground truth from your environment)
// This helps identify discrepancies between Go's ELF parsing and the actual ELF contents.
package main

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <elf-file> [readelf-path]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n  readelf-path: path to llvm-readelf or readelf (default: auto-detect)\n")
		os.Exit(1)
	}
	path := os.Args[1]
	readelfBin := ""
	if len(os.Args) >= 3 {
		readelfBin = os.Args[2]
	}

	fmt.Println("========================================")
	fmt.Println("  Method 1: Go debug/elf package")
	fmt.Println("========================================")
	goSections := dumpGoElf(path)

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  Method 2: External readelf command")
	fmt.Println("========================================")
	readelfSections := dumpReadelf(path, readelfBin)

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  Comparison (executable sections only)")
	fmt.Println("========================================")
	compareSections(goSections, readelfSections)
}

type sectionInfo struct {
	name   string
	addr   uint64
	size   uint64
	offset uint64
	flags  string
}

func dumpGoElf(path string) []sectionInfo {
	file, err := elf.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Go elf.Open failed: %v\n", err)
		return nil
	}
	defer file.Close()

	fmt.Printf("ELF file: %s\n", path)
	fmt.Printf("Class: %s, Machine: %s, ByteOrder: %s\n\n", file.Class, file.Machine, file.ByteOrder)

	fmt.Printf("%-4s %-25s %-12s %-18s %-18s %-12s %s\n",
		"Idx", "Name", "Type", "Addr", "Size", "Offset", "Flags")
	fmt.Println(strings.Repeat("-", 110))

	var execSections []sectionInfo
	for i, s := range file.Sections {
		if s == nil {
			continue
		}
		isExec := s.Type == elf.SHT_PROGBITS && s.Flags&elf.SHF_EXECINSTR != 0
		marker := "  "
		if isExec {
			marker = ">>"
		}
		fmt.Printf("%-2s%-2d %-25s %-12s 0x%016x 0x%016x 0x%08x %s\n",
			marker, i, s.Name, s.Type, s.Addr, s.Size, s.Offset, s.Flags)
		if isExec {
			// Also check what s.Data() actually returns.
			data, dataErr := s.Data()
			dataLen := uint64(0)
			if dataErr == nil {
				dataLen = uint64(len(data))
			}
			if dataLen != s.Size {
				fmt.Printf("     *** Data() returned %d (0x%x) bytes, header says %d (0x%x) — MISMATCH ***\n",
					dataLen, dataLen, s.Size, s.Size)
			}
			if dataErr != nil {
				fmt.Printf("     *** Data() error: %v ***\n", dataErr)
			}
			execSections = append(execSections, sectionInfo{
				name:   s.Name,
				addr:   s.Addr,
				size:   s.Size,
				offset: s.Offset,
				flags:  s.Flags.String(),
			})
		}
	}
	fmt.Printf("\nExecutable PROGBITS sections (>>): %d\n", len(execSections))
	return execSections
}

func dumpReadelf(path, readelfBin string) []sectionInfo {
	if readelfBin == "" {
		// Auto-detect: try llvm-readelf first, then readelf.
		for _, candidate := range []string{"llvm-readelf", "readelf"} {
			if p, err := exec.LookPath(candidate); err == nil {
				readelfBin = p
				break
			}
		}
	}
	if readelfBin == "" {
		fmt.Println("No readelf found in PATH. Provide path as second argument.")
		fmt.Println("  Example: syz-dumpsections kernel.full C:\\llvm\\bin\\llvm-readelf.exe")
		return nil
	}

	fmt.Printf("Using: %s\n\n", readelfBin)

	cmd := exec.Command(readelfBin, "-S", "-W", path)
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "readelf failed: %v\n", err)
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "stderr: %s\n", exitErr.Stderr)
		}
		return nil
	}

	// Print raw readelf output.
	fmt.Println("Raw output:")
	fmt.Println(string(output))

	// Parse readelf output to extract executable sections.
	return parseReadelfSections(string(output))
}

// parseReadelfSections extracts section info from readelf -S -W output.
// Handles both GNU readelf and llvm-readelf formats.
// Example line:
//   [ 1] .text             PROGBITS        ffffffff81000000 200000 a1b2c3 00  AX  0   0 16
func parseReadelfSections(output string) []sectionInfo {
	// Match lines like: [ N] .name  TYPE  addr  offset  size  ...  flags
	re := regexp.MustCompile(`\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(\S+)`)

	var execSections []sectionInfo
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[2]
		typeName := m[3]
		addrStr := m[4]
		offsetStr := m[5]
		sizeStr := m[6]
		flags := m[7]

		addr, _ := strconv.ParseUint(addrStr, 16, 64)
		offset, _ := strconv.ParseUint(offsetStr, 16, 64)
		size, _ := strconv.ParseUint(sizeStr, 16, 64)

		// Check for executable PROGBITS (flags contain X and type is PROGBITS).
		if typeName == "PROGBITS" && strings.Contains(flags, "X") {
			execSections = append(execSections, sectionInfo{
				name:   name,
				addr:   addr,
				size:   size,
				offset: offset,
				flags:  flags,
			})
		}
	}
	fmt.Printf("Executable PROGBITS sections: %d\n", len(execSections))
	return execSections
}

func compareSections(goSecs, readelfSecs []sectionInfo) {
	if goSecs == nil || readelfSecs == nil {
		fmt.Println("Cannot compare — one or both methods failed.")
		return
	}

	// Build lookup by name for readelf sections.
	readelfByName := make(map[string]sectionInfo)
	for _, s := range readelfSecs {
		readelfByName[s.name] = s
	}

	fmt.Printf("\n%-25s %-18s %-18s %-18s %-18s %s\n",
		"Section", "Go Addr", "readelf Addr", "Go Size", "readelf Size", "Status")
	fmt.Println(strings.Repeat("-", 120))

	allMatch := true
	for _, goSec := range goSecs {
		reSec, found := readelfByName[goSec.name]
		if !found {
			fmt.Printf("%-25s 0x%016x %-18s 0x%016x %-18s %s\n",
				goSec.name, goSec.addr, "NOT FOUND", goSec.size, "NOT FOUND", "MISSING in readelf")
			allMatch = false
			continue
		}

		addrMatch := goSec.addr == reSec.addr
		sizeMatch := goSec.size == reSec.size

		status := "OK"
		if !addrMatch && !sizeMatch {
			status = "ADDR+SIZE MISMATCH"
			allMatch = false
		} else if !addrMatch {
			status = "ADDR MISMATCH"
			allMatch = false
		} else if !sizeMatch {
			status = fmt.Sprintf("SIZE MISMATCH (diff=%+d)", int64(goSec.size)-int64(reSec.size))
			allMatch = false
		}

		fmt.Printf("%-25s 0x%016x 0x%016x 0x%016x 0x%016x %s\n",
			goSec.name, goSec.addr, reSec.addr, goSec.size, reSec.size, status)

		delete(readelfByName, goSec.name)
	}

	// Sections found by readelf but not by Go.
	for _, reSec := range readelfByName {
		fmt.Printf("%-25s %-18s 0x%016x %-18s 0x%016x %s\n",
			reSec.name, "NOT FOUND", reSec.addr, "NOT FOUND", reSec.size, "MISSING in Go")
		allMatch = false
	}

	fmt.Println()
	if allMatch {
		fmt.Println("RESULT: All sections match between Go and readelf.")
		fmt.Println("The size difference you observed is NOT from Go's ELF parser.")
	} else {
		fmt.Println("RESULT: MISMATCH detected between Go and readelf.")
		fmt.Println("Go's debug/elf package is reading different values than readelf.")
		fmt.Println("This explains why coverage callback scanning misses some PCs.")
	}
}
