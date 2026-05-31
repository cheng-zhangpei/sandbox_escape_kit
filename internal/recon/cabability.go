package recon

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
)

// collectCapability 采集 Layer 2: 权限与 capability
// 运行位置: 容器内
//
// 关键判断:
//
//	IsPrivileged → 特权容器, 直接标记高危
//	CAP_SYS_ADMIN → release_agent / mount / cgroup 全能
//	CAP_SYS_PTRACE → ptrace 宿主进程
//	CAP_DAC_READ_SEARCH → 读任意文件
func collectCapability() CapabilityInfo {
	info := CapabilityInfo{}

	parseProcStatus(&info)
	detectPrivileged(&info)
	detectDangerousCaps(&info)

	return info
}

// parseProcStatus 从 /proc/self/status 提取 capability 和 UID
func parseProcStatus(info *CapabilityInfo) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return
	}
	defer f.Close()

	// 正则匹配 capability 字段
	// 格式: "CapEff:\t00000000a80425fb"
	capRe := regexp.MustCompile(`^Cap(\w+):\t([0-9a-fA-F]+)$`)
	uidRe := regexp.MustCompile(`^Uid:\t(\d+)`)
	gidRe := regexp.MustCompile(`^Gid:\t(\d+)`)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if m := capRe.FindStringSubmatch(line); len(m) > 0 {
			val, _ := strconv.ParseUint(m[2], 16, 64)
			switch m[1] {
			case "Eff":
				info.Effective = val
			case "Bnd":
				info.Bounding = val
			case "Inh":
				info.Inheritable = val
			case "Prm":
				info.Permitted = val
			}
		}

		if m := uidRe.FindStringSubmatch(line); len(m) > 0 {
			uid, _ := strconv.Atoi(m[1])
			info.UID = uid
			info.EUID = uid // 简化, 不处理 setuid 差异
		}

		if m := gidRe.FindStringSubmatch(line); len(m) > 0 {
			info.GID, _ = strconv.Atoi(m[1])
		}
	}
}

// detectPrivileged 判断是否特权容器
// 特权容器的 CapEff = 0000003fffffffff (全能力)
func detectPrivileged(info *CapabilityInfo) {
	fullCap := uint64(0x0000003fffffffff)
	fullCapAlt := uint64(0x0000001fffffffff) // 某些版本用这个

	info.IsPrivileged = (info.Effective == fullCap || info.Effective == fullCapAlt)
}

// detectDangerousCaps 找出激活的危险 capability
// 每个 capability 对应一个 bit 位
func detectDangerousCaps(info *CapabilityInfo) {
	// 危险 capability 列表 (bit 位号)
	// 这些能力如果被激活, 攻击面会大幅增加
	dangerous := map[int]string{
		2:  "CAP_DAC_READ_SEARCH",    // open_by_handle_at() 读任意文件
		16: "CAP_SYS_MODULE",         // insmod 恶意内核模块
		17: "CAP_SYS_RAWIO",          // /dev/mem 直接操作内存
		19: "CAP_SYS_PTRACE",         // ptrace 宿主进程
		21: "CAP_SYS_ADMIN",          // mount/cgroup/bpf 全能 — 逃逸门票
		33: "CAP_MAC_ADMIN",          // AppArmor 规则修改
		39: "CAP_BPF",                // BPF 程序注入
		40: "CAP_CHECKPOINT_RESTORE", // 特定场景提权
	}

	for bit, name := range dangerous {
		if info.Effective&(1<<bit) != 0 {
			info.DangerousCaps = append(info.DangerousCaps, bit)
			info.ActiveNames = append(info.ActiveNames, name)
		}
	}
}
