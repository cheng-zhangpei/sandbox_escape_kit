package recon

import (
	"fmt"
	"os"
	"strings"
)

// collectProc 采集 /proc 相关信息
// 运行位置: 容器内
//
// 核心攻击点:
//
//	core_pattern 可写 → 触发 coredump 在宿主执行任意命令
//	modprobe 可写 → 内核加载模块时执行任意命令
//	fd 泄漏 → CVE-2024-21626
func collectProc() ProcInfo {
	info := ProcInfo{}

	// 测试关键 /proc/sys 路径的写权限
	info.CorePatternWritable = writable("/proc/sys/kernel/core_pattern")
	info.CorePatternValue = readFirstLine("/proc/sys/kernel/core_pattern")
	info.ModprobeWritable = writable("/proc/sys/kernel/modprobe")
	info.ModprobeValue = readFirstLine("/proc/sys/kernel/modprobe")
	info.HotplugWritable = writable("/proc/sys/kernel/hotplug")
	info.SysrqWritable = writable("/proc/sysrq-trigger")

	// 容器能否读宿主的 /proc/1/root
	// 如果能读, 说明和宿主共享 PID namespace
	info.Proc1RootReadable = dirReadable("/proc/1/root")

	// fd 泄漏检测
	info.FdLeaks = detectFdLeaks()

	// 能看到多少宿主进程
	info.VisibleHostPids = countVisiblePids()

	return info
}

// readFirstLine 读文件第一行
func readFirstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func dirReadable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// detectFdLeaks 检测容器进程的 fd 泄漏
// CVE-2024-21626: runc 的 fd 泄漏到宿主根目录
//
// 正常的 fd 指向: /dev/null, /dev/zero, pipe:[], socket:[]
// 异常的 fd 指向: 宿主路径, 包含 docker/overlay2/containerd
func detectFdLeaks() []FdLeak {
	var leaks []FdLeak

	// 正常 fd 列表, 排除这些
	normalTargets := map[string]bool{
		"/dev/null":    true,
		"/dev/zero":    true,
		"/dev/urandom": true,
		"/dev/random":  true,
		"/dev/tty":     true,
		"/dev/console": true,
		"/dev/full":    true,
	}

	// 扫描 /proc/self/fd/
	selfFds, _ := os.ReadDir("/proc/self/fd")
	for _, fdEntry := range selfFds {
		fdNum := fdEntry.Name()
		link := readlinkSafe(fmt.Sprintf("/proc/self/fd/%s", fdNum))
		if link == "" {
			continue
		}

		// 排除正常的
		if normalTargets[link] {
			continue
		}
		if strings.HasPrefix(link, "pipe:") ||
			strings.HasPrefix(link, "socket:") ||
			strings.HasPrefix(link, "anon_inode:") {
			continue
		}

		// 判断是否指向宿主路径
		isHost := strings.Contains(link, "docker") ||
			strings.Contains(link, "overlay2") ||
			strings.Contains(link, "containerd") ||
			link == "/"

		if isHost {
			fdNumInt := 0
			fmt.Sscanf(fdNum, "%d", &fdNumInt)
			leaks = append(leaks, FdLeak{
				FD:         fdNumInt,
				Target:     link,
				IsHostPath: true,
			})
		}
	}

	// 也扫描 /proc/1/fd/ (init 进程的 fd)
	initFds, _ := os.ReadDir("/proc/1/fd")
	for _, fdEntry := range initFds {
		fdNum := fdEntry.Name()
		link := readlinkSafe(fmt.Sprintf("/proc/1/fd/%s", fdNum))
		if link == "" {
			continue
		}

		if normalTargets[link] || strings.HasPrefix(link, "pipe:") ||
			strings.HasPrefix(link, "socket:") {
			continue
		}

		isHost := strings.Contains(link, "docker") ||
			strings.Contains(link, "overlay2") ||
			link == "/"

		if isHost {
			fdNumInt := 0
			fmt.Sscanf(fdNum, "%d", &fdNumInt)
			leaks = append(leaks, FdLeak{
				PID:        1,
				FD:         fdNumInt,
				Target:     link,
				IsHostPath: true,
			})
		}
	}

	return leaks
}

// countVisiblePids 统计容器内能看到多少进程
// 如果能看到大量宿主进程, 说明 PID namespace 可能共享
func countVisiblePids() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		// 只计数字目录 (PID)
		if e.IsDir() {
			for _, c := range e.Name() {
				if c < '0' || c > '9' {
					goto skip
				}
			}
			count++
		}
	skip:
	}
	return count
}
