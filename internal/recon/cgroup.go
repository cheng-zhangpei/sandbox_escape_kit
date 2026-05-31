package recon

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// collectCgroup 采集 cgroup 层信息
// 运行位置: 容器内
//
// cgroup v1 release_agent 逃逸是最经典的容器逃逸
// 这个模块采集的前提条件:
//  1. cgroup 版本是 v1 还是 v2
//  2. 哪些子系统的 notify_on_release 可写
//  3. release_agent 是否存在且可写
//  4. cgroup.procs 是否可写 (触发逃逸的关键)
func collectCgroup() CgroupInfo {
	info := CgroupInfo{
		Subsystems: make(map[string]CgSubsystem),
	}

	info.Version = detectCgroupVersion()
	info.UnifiedPath = "/sys/fs/cgroup"

	switch info.Version {
	case 1:
		collectCgroupV1(&info)
	case 2:
		collectCgroupV2(&info)
	}

	return info
}

// detectCgroupVersion 判断 cgroup 版本
// v1: /sys/fs/cgroup/ 下有多个独立子目录 (memory, cpu, pids...)
// v2: /sys/fs/cgroup/ 下有 cgroup.controllers 文件
func detectCgroupVersion() int {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		return 2
	}
	return 1
}

// collectCgroupV1 采集 cgroup v1 每个子系统的写权限
func collectCgroupV1(info *CgroupInfo) {
	// 从 /proc/self/cgroup 获取当前容器挂载了哪些子系统
	// 格式: "12:memory:/docker/abc123"
	//        ^  ^       ^
	//        |  |       └─ 容器在该子系统下的路径
	//        |  └─ 子系统名
	//        └─ 层级 ID
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}

		subsystemName := parts[1] // "memory", "cpu" 等
		cgroupPath := parts[2]    // "/docker/abc123"

		sub := CgSubsystem{
			Name:     subsystemName,
			SelfPath: cgroupPath,
		}

		// 找到挂载点
		// v1 每个子系统独立挂载在 /sys/fs/cgroup/{name}
		mountBase := fmt.Sprintf("/sys/fs/cgroup/%s", subsystemName)
		if _, err := os.Stat(mountBase); err == nil {
			sub.MountPath = mountBase

			// 容器在该子系统下的完整路径
			fullPath := mountBase + cgroupPath

			// 测试各项写权限
			sub.ReleaseAgentExists = fileExists(mountBase + "/release_agent")
			sub.ReleaseAgentWritable = writable(mountBase + "/release_agent")
			sub.NotifyOnReleaseWritable = writable(fullPath + "/notify_on_release")
			sub.CgroupProcsWritable = writable(fullPath + "/cgroup.procs")

			// 能否创建子目录 (mkdir 能力)
			sub.SubDirs = listSubDirs(fullPath)
		}

		info.Subsystems[subsystemName] = sub
	}
}

// collectCgroupV2 采集 cgroup v2 信息
// v2 没有 release_agent, 但有 subtree_control
func collectCgroupV2(info *CgroupInfo) {
	unified := "/sys/fs/cgroup"

	// 读取容器的 cgroup 路径
	data, _ := os.ReadFile("/proc/self/cgroup")
	selfPath := ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		// v2 格式: "0::/docker/abc123"
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) == 3 && parts[0] == "0" {
			selfPath = parts[2]
		}
	}

	fullPath := unified + selfPath

	sub := CgSubsystem{
		Name:                   "unified",
		MountPath:              unified,
		SelfPath:               selfPath,
		CgroupProcsWritable:    writable(fullPath + "/cgroup.procs"),
		SubtreeControlWritable: writable(fullPath + "/cgroup.subtree_control"),
		SubDirs:                listSubDirs(fullPath),
	}

	info.Subsystems["unified"] = sub
	info.SubtreeControlWritable = sub.SubtreeControlWritable
	info.DevicesAllowWritable = false // v2 没有 devices.allow
}

// writable 测试文件是否可写
// 用 os.OpenFile 直接试, 不靠猜测
func writable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func listSubDirs(path string) []string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	return dirs
}
