package main

import (
	"fmt"
	"sandbox_escape_kit/internal/recon"
)

func main() {
	result := recon.Collect()
	k := result.Kernel

	fmt.Println("════════════════════════════════════════")
	fmt.Println("  Kernel Recon Results")
	fmt.Println("════════════════════════════════════════")
	fmt.Printf("  Release:      %s\n", k.Release)
	fmt.Printf("  Version:      %d.%d.%d\n", k.Version[0], k.Version[1], k.Version[2])
	fmt.Printf("  Arch:         %s\n", k.Arch)
	fmt.Printf("  CompileDate:  %s\n", k.CompileDate)
	fmt.Printf("  Cmdline:      %s\n", k.Cmdline)
	fmt.Printf("  Modules:      %d loaded\n", len(k.Modules))
	fmt.Printf("  ConfigFlags:  %d entries\n", len(k.ConfigFlags))

	// 关键配置项 — 这些直接决定攻击面
	interesting := []string{
		"CONFIG_USER_NS",
		"CONFIG_OVERLAY_FS",
		"CONFIG_BPF_SYSCALL",
		"CONFIG_SECURITY_YAMA",
		"CONFIG_NETFILTER_XT_MATCH_CONNTRACK",
		"CONFIG_IKCONFIG_PROC",
	}

	fmt.Println("\n════════════════════════════════════════")
	fmt.Println("  Key Config Flags (Attack Surface)")
	fmt.Println("════════════════════════════════════════")
	for _, flag := range interesting {
		if val, ok := k.ConfigFlags[flag]; ok {
			status := "✗ disabled"
			if val {
				status = "✓ enabled"
			}
			fmt.Printf("  %-45s %s\n", flag, status)
		} else {
			fmt.Printf("  %-45s   not found\n", flag)
		}
	}

	// 模块列表
	fmt.Println("\n════════════════════════════════════════")
	fmt.Printf("  Loaded Modules (showing first 15 of %d)\n", len(k.Modules))
	fmt.Println("════════════════════════════════════════")
	for i, m := range k.Modules {
		if i >= 15 {
			fmt.Printf("  ... and %d more\n", len(k.Modules)-15)
			break
		}
		fmt.Printf("  %s\n", m)
	}
}
