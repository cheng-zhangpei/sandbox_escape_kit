package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sandbox_escape_kit/internal/recon"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  sek collect --target <host|container> [-o output.json]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "collect":
		cmdCollect()
	default:
		fmt.Println("unknown command")
		os.Exit(1)
	}
}

func cmdCollect() {
	target := ""
	outputPath := ""

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--target":
			if i+1 < len(os.Args) {
				target = os.Args[i+1]
				i++
			}
		case "-o":
			if i+1 < len(os.Args) {
				outputPath = os.Args[i+1]
				i++
			}
		}
	}

	if target != "host" && target != "container" {
		fmt.Fprintf(os.Stderr, "error: --target must be 'host' or 'container'\n")
		os.Exit(1)
	}

	result := recon.Collect(target)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
		os.Exit(1)
	}

	if outputPath != "" {
		os.WriteFile(outputPath, data, 0644)
		fmt.Fprintf(os.Stderr, "saved to %s\n", outputPath)
	} else {
		fmt.Println(string(data))
	}
}
