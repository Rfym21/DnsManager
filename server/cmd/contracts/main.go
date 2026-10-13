package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dns-manager/dnsmgr/server/internal/contracts"
	"os"
	"path/filepath"
)

func main() {
	write := flag.Bool("write", false, "write OpenAPI and TypeScript artifacts")
	check := flag.Bool("check", false, "fail if generated artifacts differ from live routes or models")
	rootFlag := flag.String("root", "", "repository root (auto-detected by default)")
	flag.Parse()
	root := *rootFlag
	if root == "" {
		root, _ = os.Getwd()
		for {
			if _, err := os.Stat(filepath.Join(root, "server/go.mod")); err == nil {
				break
			}
			parent := filepath.Dir(root)
			if parent == root {
				fmt.Fprintln(os.Stderr, "repository root not found")
				os.Exit(1)
			}
			root = parent
		}
	}
	if *write || *check {
		if err := contracts.Generate(root, *check); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("OpenAPI and TypeScript contracts are current")
		return
	}
	document, err := contracts.Document(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(document); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
