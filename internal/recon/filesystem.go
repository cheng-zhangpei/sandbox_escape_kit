package recon

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// collectFilesystem 采集 Layer 1+3: 文件系统信息
// 运行位置: 容器内
//
// 关键点:
//   - SUID 二进制 → 直接提权
//   - 宿主根目录挂载 → 一键逃逸
//   - overlay upperdir → release_agent payload 路径
func collectFilesystem() FilesystemInfo {
	info := FilesystemInfo{}

	info.Mounts = parseMounts()
	scanDevices(&info)
	scanSuidBinaries(&info)
	scanWritablePaths(&info)
	info.HostRootMounted = checkHostRootMount(info.Mounts)

	return info
}

// parseMounts 解析 /proc/self/mountinfo
// 这是整个文件系统采集的核心
func parseMounts() []MountEntry {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()

	var mounts []MountEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		entry := parseMountLine(scanner.Text())
		mounts = append(mounts, entry)
	}
	return mounts
}

// parseMountLine 解析单行 mountinfo
// 格式:
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext4 /dev/root rw,errors=continue
//	字段:       [3]     [4]    [5]          [6..n-3]  [n-2] [n-1]     [n]
//	                   root  mount_point   选项       fs_type  source  super_opts
func parseMountLine(line string) MountEntry {
	entry := MountEntry{}

	// 以 " - " 分隔, 左边是内核字段, 右边是 fs 字段
	separator := " - "
	idx := strings.Index(line, separator)
	if idx < 0 {
		return entry
	}

	left := strings.Fields(line[:idx])
	right := strings.Fields(line[idx+len(separator):])

	// 左边: 至少有 6 个字段
	if len(left) >= 6 {
		entry.Target = left[4]  // 挂载点
		entry.Options = left[5] // 选项
		entry.IsReadOnly = strings.Contains(left[5], "ro") &&
			!strings.Contains(left[5], "rw")
	}

	// 右边: fs_type, mount_source, super_options
	if len(right) >= 2 {
		entry.FSType = right[0]
		entry.Source = right[1]
	}
	if len(right) >= 3 {
		superOpts := right[2]

		// overlay 特有字段在 super_options 里
		reUpper := regexp.MustCompile(`upperdir=([^,\s]+)`)
		if m := reUpper.FindStringSubmatch(superOpts); len(m) > 1 {
			entry.UpperDir = m[1]
		}

		reWork := regexp.MustCompile(`workdir=([^,\s]+)`)
		if m := reWork.FindStringSubmatch(superOpts); len(m) > 1 {
			entry.WorkDir = m[1]
		}

		reLower := regexp.MustCompile(`lowerdir=([^,\s]+)`)
		if m := reLower.FindStringSubmatch(superOpts); len(m) > 1 {
			entry.LowerDirs = strings.Split(m[1], ":")
		}
	}

	return entry
}

// scanDevices 扫描 /dev 下的块设备和危险设备
func scanDevices(info *FilesystemInfo) {
	dangerousDevices := []string{
		"/dev/mem", "/dev/kmem", // 直接内存访问
		"/dev/fuse",            // FUSE 文件系统
		"/dev/sda", "/dev/vda", // 块设备
	}

	entries, _ := os.ReadDir("/dev")
	for _, e := range entries {
		name := "/dev/" + e.Name()
		for _, d := range dangerousDevices {
			if name == d {
				info.DangerousDevices = append(info.DangerousDevices, name)
			}
		}
	}

	// 扫描所有块设备
	blockRe := regexp.MustCompile(`^(sd|vd|nvme|dm-)\w+`)
	for _, e := range entries {
		if blockRe.MatchString(e.Name()) {
			info.BlockDevices = append(info.BlockDevices, "/dev/"+e.Name())
		}
	}
}

// scanSuidBinaries 扫描 SUID 二进制
// 只扫白名单目录, 限制数量和超时
func scanSuidBinaries(info *FilesystemInfo) {
	// 已知可利用的 SUID 二进制 (GTFOBins 子集)
	exploitable := map[string]string{
		"/usr/bin/nmap":    "nmap --interactive → !sh",
		"/usr/bin/python":  "python -c 'import os;os.execl(...)'",
		"/usr/bin/python3": "python3 -c 'import os;os.execl(...)'",
		"/usr/bin/perl":    "perl -e 'exec \"/bin/sh\";'",
		"/usr/bin/ruby":    "ruby -e 'exec \"/bin/sh\"'",
		"/usr/bin/lua":     "lua -e 'os.execute(\"/bin/sh\")'",
		"/usr/bin/env":     "env /bin/sh -p",
		"/usr/bin/find":    "find / -exec /bin/sh \\;",
		"/usr/bin/vim":     "vim -c ':!sh'",
		"/usr/bin/vi":      "vi -c ':!sh'",
		"/usr/bin/less":    "less → !sh",
		"/usr/bin/more":    "more → !sh",
		"/usr/bin/awk":     "awk 'BEGIN {system(\"/bin/sh\")}'",
		"/usr/bin/bash":    "直接 sh -p",
	}

	scanDirs := []string{
		"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin",
	}

	count := 0
	maxScan := 5000

	for _, dir := range scanDirs {
		filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			count++
			if count > maxScan {
				return filepath.SkipDir
			}

			// 检查 SUID 位
			if fi.Mode()&os.ModeSetuid != 0 {
				bin := SuidBinary{
					Path:          path,
					IsExploitable: false,
				}
				if method, ok := exploitable[path]; ok {
					bin.IsExploitable = true
					bin.ExploitMethod = method
				}
				info.SuidBinaries = append(info.SuidBinaries, bin)
			}
			return nil
		})
	}
}

// scanWritablePaths 测试关键路径是否可写
func scanWritablePaths(info *FilesystemInfo) {
	testPaths := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/crontab",
		"/root/.ssh",
		"/proc/sys",
	}

	for _, p := range testPaths {
		if writable(p) {
			info.WritablePaths = append(info.WritablePaths, p)
		}
	}
}

// checkHostRootMount 检查宿主根目录是否被挂载进来
// 这是最危险的配置之一 — 直接读写宿主文件系统
func checkHostRootMount(mounts []MountEntry) bool {
	for _, m := range mounts {
		// 宿主根目录挂载通常表现为:
		//   mount -v /:/host
		//   或者 mount source 是 / 且 target 不是 /
		if m.Source == "/" && m.Target != "/" && !m.IsReadOnly {
			return true
		}
		// 也可能是 docker.sock 所在的 /var/run 被挂进来
		// 但那个在 runtime.go 已经检测了
	}
	return false
}
