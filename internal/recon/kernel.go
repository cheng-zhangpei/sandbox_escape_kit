package recon

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// collectKernel 采集 Layer 1 内核层信息
// 所有后续分析的基石: CVE 匹配、攻击面判定都从这里开始
func collectKernel() KernelInfo {
	k := KernelInfo{
		ConfigFlags: make(map[string]bool),
	}
	// kernel 一共包括下面几个部分：版本、架构、已加载模块、启动参数、变异选项
	parseProcVersion(&k)      // /proc/version → Version, Release, CompileDate
	k.Arch = getArch()        // uname syscall → 架构
	k.Modules = loadModules() // /proc/modules → 已加载模块
	k.Cmdline = readCmdline() // /proc/cmdline → 启动参数
	loadConfigFlags(&k)       // /proc/config.gz → 编译选项

	return k
}

// parseProcVersion 解析 /proc/version
//
// 为什么 Version 用 [3]int 而不是 string?
// 因为 Analyze 阶段要做范围比较: kernel.Version < [3]int{5,17,0}
// 整数比较比字符串比较靠谱, 不会出 "5.9" > "5.15" 这种问题
func parseProcVersion(k *KernelInfo) {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return // 容器里可能挂了 proc 只读, 不致命
	}
	line := string(data)

	// 提取 release 字符串: "5.15.0-91-generic"
	re := regexp.MustCompile(`Linux version (\S+)`)
	if m := re.FindStringSubmatch(line); len(m) > 1 {
		k.Release = m[1]

		// 从 "5.15.0-91-generic" 中提取纯版本号 "5.15.0"
		// 先按 "-" 分割取第一段, 再按 "." 分割
		baseVersion := strings.SplitN(k.Release, "-", 2)[0]
		parts := strings.Split(baseVersion, ".")
		for i := 0; i < 3 && i < len(parts); i++ {
			k.Version[i], _ = strconv.Atoi(parts[i])
		}
	}

	// 提取编译日期, 在行尾
	// 格式: "Tue Nov 14 13:30:08 UTC 2023"
	// 不是所有内核都有这个字段, 没有就留空
	re2 := regexp.MustCompile(
		`(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+[\d:]+\s+\w+\s+\d{4}`,
	)
	if m := re2.FindString(line); m != "" {
		k.CompileDate = m
	}
}

// getArch 通过 uname 系统调用获取架构
// 不用 exec("uname -m") 的原因:
//  1. exec 开销大, 还要处理 PATH 找不到的问题
//  2. syscall 更可靠, 在最小化容器里也能工作
//  3. 不依赖容器里有没有 uname 二进制
//
// IDV 终端可能是 ARM (aarch64), 架构影响:
//   - shellcode 的字节码完全不同
//   - 某些内核 exploit 只有 x86_64 版本
//   - /proc/config.gz 里的配置项可能不同
func getArch() string {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return "unknown"
	}
	return int8ToString(uts.Machine[:])
}

// int8ToString 把 C 风格的 [65]int8 数组转成 Go string
// Utsname 结构体里所有字段都是 [65]int8, 这是 Linux syscall 的固定写法
func int8ToString(arr []int8) string {
	buf := make([]byte, 0, len(arr))
	for _, b := range arr {
		if b == 0 { // C 字符串以 \0 结尾
			break
		}
		buf = append(buf, byte(b))
	}
	return string(buf)
}

// loadModules 解析 /proc/modules
// 格式: 每行 "模块名 引用计数 引用者列表 状态 地址"
// 例如: "overlay 145352 2 - Live 0xffffffffc0a3a000"
//
// 我们只取第一列(模块名), 部分模块有直接的攻击意义:
//   - overlay       → overlayfs 可用, CVE-2023-0386 前提
//   - nf_tables     → nf_tables 相关提权漏洞
//   - veth/bridge   → 网络逃逸路径
//   - binder        → Android 相关, agent 沙箱场景可能遇到
func loadModules() []string {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil // 容器里 /proc/modules 可能不可读
	}
	defer f.Close()

	var modules []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// 每行第一个空格前就是模块名
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			modules = append(modules, fields[0])
		}
	}
	return modules
}

// readCmdline 读取 /proc/cmdline
// 内核启动参数包含安全相关配置, 关键的有:
//
//	lockdown=confidentiality  → 内核锁定模式, 很多操作被禁止
//	apparmor=0                → AppArmor 禁用
//	enforcing=0               → SELinux permissive
//	namespace.unpriv_enable=1 → 允许非特权用户创建 namespace
//	cgroup_no_v1=memory       → 禁用了某些 cgroup v1 子系统
//
// 这些信息和 Security 层互补, 这里拿到的是启动时的配置意图
func readCmdline() string {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// loadConfigFlags 加载内核编译时的配置选项
//
// 为什么编译选项这么重要?
// 因为很多攻击路径的前提是"内核编译时启用了某个特性":
//
//	CONFIG_USER_NS=y    → 可以 unshare 创建 user namespace → CVE-2022-0492 的前提
//	CONFIG_OVERLAY_FS=y → overlayfs 可用 → CVE-2023-0386 的前提
//	CONFIG_BPF_SYSCALL=y → bpf() syscall 可用 → 内核 exploit 面增加
//	CONFIG_SECURITY_YAMA=y → ptrace 受限 → pid namespace ptrace 攻击可能不可用
//	CONFIG_NETFILTER_XT_MATCH_CONNTRACK → nf_tables 相关 CVE 条件
//
// 采集优先级:
//  1. /proc/config.gz — 运行中内核的配置, 最准确
//  2. /boot/config-$(uname -r) — 可能不存在或和运行中的内核不匹配
//  3. 都没有 → ConfigFlags 留空, Analyze 阶段基于版本号做保守估计
func loadConfigFlags(k *KernelInfo) {
	// 方法1: /proc/config.gz (大多数发行版启用 CONFIG_IKCONFIG_PROC)
	if data, err := readGzipFile("/proc/config.gz"); err == nil {
		parseConfigData(data, k)
		return
	}
	// 方法2: /boot/config-* (容器里通常没有 /boot)
	bootConfig := fmt.Sprintf("/boot/config-%s", k.Release)
	if data, err := os.ReadFile(bootConfig); err == nil {
		parseConfigData(string(data), k)
	}
}

func readGzipFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gr.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(gr); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// parseConfigData 解析内核 config
// 两种格式:
//
//	CONFIG_XXX=y                    → 编译进内核
//	CONFIG_XXX=m                    → 可加载模块
//	# CONFIG_XXX is not set         → 明确禁用
//
// 对于攻击分析:
//
//	=y 和 =m 都表示"内核支持这个功能"
//	=n 或 "is not set" 表示"不可用"
func parseConfigData(data string, k *KernelInfo) {
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "CONFIG_") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				k.ConfigFlags[parts[0]] = (parts[1] == "y" || parts[1] == "m")
			}
		} else if strings.HasPrefix(line, "# CONFIG_") &&
			strings.HasSuffix(line, "is not set") {
			// "# CONFIG_XXX is not set" → 明确禁用
			key := strings.TrimPrefix(line, "# ")
			key = strings.TrimSuffix(key, " is not set")
			k.ConfigFlags[key] = false
		}
	}
}
