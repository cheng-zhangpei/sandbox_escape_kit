package recon

import (
	"fmt"
	"os"
	"syscall"
)

// collectNamespace 采集当前进程的 namespace 信息
//
// 运行位置:
//
//	--target host      → 采集宿主机的 namespace inode
//	--target container → 采集容器内的 namespace inode
//
// 两边都跑一遍, 拿到两套 inode 数据
// 分析器拿两边的 inode 做对比, 就知道哪些 namespace 是共享的
//
// 对比逻辑:
//
//	host 的 /proc/self/ns/pid 的 inode   == container 的 /proc/self/ns/pid 的 inode ?
//	如果相等 → pid namespace 共享 → 可以 ptrace 宿主进程
func collectNamespace() NamespaceInfo {
	info := NamespaceInfo{
		Entries: make(map[string]NsEntry),
	}

	nsNames := []string{
		"pid",
		"net",
		"mnt",
		"user",
		"cgroup",
		"ipc",
		"uts",
	}

	for _, name := range nsNames {
		entry := probeNamespace(name)
		info.Entries[name] = entry
	}

	info.UserNsCreated = probeUserNsCreation()

	return info
}

func probeNamespace(name string) NsEntry {
	entry := NsEntry{
		Name:      name,
		Available: true,
	}

	selfPath := fmt.Sprintf("/proc/self/ns/%s", name)
	selfTarget, err := os.Readlink(selfPath)
	if err != nil {
		entry.Available = false
		return entry
	}
	entry.Inode = selfTarget

	initPath := fmt.Sprintf("/proc/1/ns/%s", name)
	initTarget, err := os.Readlink(initPath)
	if err != nil {
		// 读不到 /proc/1/ns/*，可能是权限不足
		// 宿主模式下 self 和 PID 1 在同一个 namespace，用 self 的值
		entry.InitInode = selfTarget
		return entry
	}
	entry.InitInode = initTarget

	return entry
}

// probeUserNsCreation 测试能否创建新 user namespace
func probeUserNsCreation() bool {
	const CLONE_NEWUSER = 0x10000000

	_, _, errno := syscall.RawSyscall(
		syscall.SYS_UNSHARE,
		uintptr(CLONE_NEWUSER),
		0,
		0,
	)

	return errno == 0
}
