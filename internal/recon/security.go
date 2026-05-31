package recon

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const (
	sysBPF         = 321 // x86_64
	sysUserfaultfd = 323 // x86_64
)

func testBpf() syscall.Errno {
	_, _, errno := syscall.RawSyscall(sysBPF, 0, 0, 0)
	return errno
}

func testUserfaultfd() syscall.Errno {
	_, _, errno := syscall.RawSyscall(sysUserfaultfd, 0, 0, 0)
	return errno
}

// collectSecurity 采集 Layer 4: 安全策略
// 运行位置: 容器内
//
// 安全策略决定了哪些攻击路径被卡住了:
//
//	seccomp block mount → release_agent 用不了 (除非用 CVE-2022-0492 绕过)
//	AppArmor docker-default → 限制文件操作
//	SELinux enforcing → 限制进程权限
func collectSecurity(capInfo CapabilityInfo) SecurityInfo {
	info := SecurityInfo{
		SyscallReachable: make(map[string]bool),
	}

	parseSeccompMode(&info)
	parseAppArmor(&info)
	parseSELinux(&info)
	parseNoNewPrivs(&info)
	info.ReadOnlyRootfs = checkReadOnlyRootfs()
	testSyscalls(&info)
	// 根据capability去看系统调用是否真的可以调用
	consolidateSyscallStatus(&info, &capInfo)

	return info
}

// parseSeccompMode 从 /proc/self/status 提取 seccomp 模式
func parseSeccompMode(info *SecurityInfo) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return
	}
	defer f.Close()

	re := regexp.MustCompile(`^Seccomp:\s+(\d+)$`)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if m := re.FindStringSubmatch(scanner.Text()); len(m) > 1 {
			info.SeccompMode, _ = strconv.Atoi(m[1])
		}
	}
}

// parseAppArmor 读取 AppArmor profile
func parseAppArmor(info *SecurityInfo) {
	data, err := os.ReadFile("/proc/self/attr/current")
	if err != nil {
		return
	}
	info.AppArmorProfile = strings.TrimSpace(string(data))
}

// parseSELinux 检测 SELinux 状态
func parseSELinux(info *SecurityInfo) {
	// /sys/fs/selinux/ 存在说明 SELinux 内核模块加载了
	if _, err := os.Stat("/sys/fs/selinux"); err != nil {
		info.SELinuxMode = "Disabled"
		return
	}

	// 检查 enforcing 模式
	data, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		info.SELinuxMode = "Unknown"
		return
	}

	val := strings.TrimSpace(string(data))
	if val == "1" {
		info.SELinuxMode = "Enforcing"
	} else {
		info.SELinuxMode = "Permissive"
	}
}

// parseNoNewPrivs 检查 PR_SET_NO_NEW_PRIVS
// 如果设置了, 容器内进程无法通过 setuid 提权
func parseNoNewPrivs(info *SecurityInfo) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return
	}
	defer f.Close()

	re := regexp.MustCompile(`^NoNewPrivs:\s+(\d+)$`)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if m := re.FindStringSubmatch(scanner.Text()); len(m) > 1 {
			info.NoNewPrivs = m[1] == "1"
		}
	}
}

// checkReadOnlyRootfs 检查根文件系统是否只读
func checkReadOnlyRootfs() bool {
	// 尝试写一个临时文件到 /
	f, err := os.CreateTemp("/", ".sek_test_*")
	if err != nil {
		return true // 写不了 → 只读
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return false
}
func testMount() syscall.Errno {
	// mount 无效参数, 只看返回值
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_MOUNT,
		0, 0, 0,
	)
	return errno
}

func testUnshare() syscall.Errno {
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_UNSHARE,
		uintptr(syscall.CLONE_NEWNS),
		0, 0,
	)
	return errno
}

func testPtrace() syscall.Errno {
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_PTRACE,
		uintptr(syscall.PTRACE_TRACEME),
		0, 0,
	)
	return errno
}

func testKeyctl() syscall.Errno {
	// keyctl 系统调用号
	// x86_64: 250
	_, _, errno := syscall.RawSyscall(
		250,
		0, 0, 0,
	)
	return errno
}
func testSyscalls(info *SecurityInfo) {
	tests := []struct {
		name string
		call func() syscall.Errno
	}{
		{"mount", testMount},
		{"unshare", testUnshare},
		{"ptrace", testPtrace},
		{"bpf", testBpf},
		{"userfaultfd", testUserfaultfd},
		{"keyctl", testKeyctl},
	}

	for _, t := range tests {
		errno := t.call()
		info.SyscallReachable[t.name] = syscallReachable(errno) // 改这里
	}
}

// syscallReachable 判断 syscall 是否真正可达
//
//	ENOSYS (38) → syscall 被 seccomp block
//	EPERM  (1)  → Docker 默认 seccomp 返回这个，也是被 block
//	EINVAL (22) → 参数不对，但 syscall 可达
//	EACCES (13) → 权限不够，但 syscall 可达
//	0          → 直接成功
func syscallReachable(errno syscall.Errno) bool {
	switch errno {
	case syscall.ENOSYS, syscall.EPERM:
		return false
	default:
		return true
	}
}

// consolidateSyscallStatus 综合 seccomp 和 capability 判断 syscall 的真实可用性
// SyscallReachable 只看 seccomp 是否拦截
// SyscallBlocked 综合 seccomp + capability，是真正的"能不能用"
func consolidateSyscallStatus(info *SecurityInfo, capInfo *CapabilityInfo) {
	if info.SyscallReachable == nil {
		return
	}
	info.SyscallBlocked = make(map[string]bool)

	// syscall 需要的 capability
	requiredCaps := map[string]int{
		"mount":       21, // CAP_SYS_ADMIN
		"unshare":     21, // CAP_SYS_ADMIN (for CLONE_NEWNS)
		"ptrace":      19, // CAP_SYS_PTRACE
		"bpf":         39, // CAP_BPF
		"userfaultfd": 21, // CAP_SYS_ADMIN
		"keyctl":      21, // CAP_SYS_ADMIN (近似)
	}

	for name, reachable := range info.SyscallReachable {
		if !reachable {
			// 被 seccomp 拦了
			info.SyscallBlocked[name] = true
			continue
		}

		// syscall 可达，但有没有对应的 capability?
		if capBit, ok := requiredCaps[name]; ok {
			if capInfo.Effective&(1<<capBit) == 0 {
				// 没有对应 capability
				info.SyscallBlocked[name] = true
			}
		}
	}
}
