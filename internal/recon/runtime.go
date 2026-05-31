package recon

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// collectRuntime 采集运行时层信息
//
// 这一层的采集决定了：
//  1. 我们在哪个容器运行时里（Docker/Podman/containerd）
//  2. 有哪些特定的逃逸路径（runc fd leak、socket 滥用）
//  3. 容器在宿主上的路径在哪（release_agent 的关键）
func collectRuntime() RuntimeInfo {
	r := RuntimeInfo{
		EnvLeaks: make(map[string]string),
	}

	detectRuntimeType(&r)   // /.dockerenv, /run/.containerenv 等指纹
	detectVersions(&r)      // runc --version
	readInitProc(&r)        // /proc/1/cmdline, /proc/1/exe
	findSockets(&r)         // docker.sock, containerd.sock
	detectStorageDriver(&r) // 从 mountinfo 推断
	detectHostPath(&r)      // 容器在宿主上的绝对路径 — 最关键
	leakSensitiveEnv(&r)    // 环境变量泄露

	return r
}

// detectRuntimeType 通过文件指纹判断容器运行时类型
//
// 为什么要知道运行时类型?
//   - Docker: 可能有 docker.sock → 直接 API 控制宿主
//   - Podman: 无 daemon，但可能有 conmon 进程
//   - runc: CVE-2024-21626 (fd 泄漏) 需要知道是 runc
//   - gVisor/Kata: 有额外隔离，经典逃逸路径可能不适用
//
// 判断顺序很重要——先看特定文件，再看通用指纹
func detectRuntimeType(r *RuntimeInfo) {
	// 最确定的指纹
	if fileExists("/.dockerenv") {
		r.Type = RuntimeDocker
		return
	}
	if fileExists("/run/.containerenv") {
		r.Type = RuntimePodman
		return
	}

	// 次确定: 从 /proc/1/cgroup 推断
	// Docker 容器的 cgroup 路径通常包含 "docker"
	// containerd 的通常包含 "containerd" 或 "cri-containerd"
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		content := string(data)
		if strings.Contains(content, "docker") {
			r.Type = RuntimeDocker
			return
		}
		if strings.Contains(content, "containerd") ||
			strings.Contains(content, "cri-containerd") {
			r.Type = RuntimeContainerd
			return
		}
	}

	// 最后看 /proc/1/init 进程名
	// 不同运行时的 init 进程不同:
	//   Docker:     /usr/bin/docker-init (tini) 或直接 /bin/sh
	//   Podman:     conmon + runc
	//   containerd: containerd-shim-runc-v2
	//   LXC:        /sbin/init
	initExe := readlinkSafe("/proc/1/exe")
	if strings.Contains(initExe, "containerd-shim") {
		r.Type = RuntimeContainerd
		return
	}
	if strings.Contains(initExe, "lxc-init") {
		r.Type = RuntimeLXC
		return
	}

	r.Type = RuntimeUnknown
}

// detectVersions 获取运行时和 runc 版本
//
// 版本信息的攻击意义:
//
//	runc < 1.1.12  → CVE-2024-21626 (fd 泄漏到宿主)
//	Docker < 25.0  → 某些 API 绕过
//
// runc --version 是整个采集引擎里唯一允许的 exec 命令
// 原因: runc 版本无法通过 /proc 或 /sys 获取，必须 exec
// 其他所有信息都通过读文件/syscall 获取
func detectVersions(r *RuntimeInfo) {
	// runc --version 输出类似:
	//   runc version 1.1.9
	//   commit: v1.1.9-0-gccaecfc
	//   spec: 1.0.2-dev
	//   go: go1.21.5
	//   libseccomp: 2.5.4
	//
	// 我们只关心第一行的版本号
	output, err := execCommand("runc", "--version")
	if err == nil {
		re := regexp.MustCompile(`runc version (\S+)`)
		if m := re.FindStringSubmatch(output); len(m) > 1 {
			r.RuncVersion = m[1]
		}
	}

	// Docker 版本 (如果有的话)
	// 容器内通常没有 docker CLI，所以从 socket API 或环境变量推断
	// 这里先留空，后面从 EnvLeaks 或 socket 探测时补充
}

// execCommand 执行外部命令，返回 stdout
// 这是整个 recon 引擎里唯一的 exec 调用点
// 其他所有采集都通过读文件和 syscall 完成
func execCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// fileExists 判断文件/目录是否存在
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// readlinkSafe 安全地读取符号链接，失败返回空字符串
func readlinkSafe(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return target
}

// readInitProc 采集容器 PID 1 的信息
//
// PID 1 的信息有什么用?
//
//  1. InitCmdline → 判断容器启动方式
//     - "/sbin/init" → 系统级容器(可能有更多攻击面)
//     - "/bin/sh" → 最小容器
//     - "nginx -g daemon off;" → 应用容器
//
//  2. InitExe → runc 初始化的痕迹
//     - 正常: /proc/1/exe → /usr/bin/docker-init (tini)
//     - 异常: /proc/1/exe → /proc/self/fd/3 (fd 泄漏! CVE-2024-21626)
//
//  3. 和宿主共享 PID namespace 时, /proc/1 就是宿主的 init
//     这时候 readlink /proc/1/exe 会指向 /sbin/init (systemd)
func readInitProc(r *RuntimeInfo) {
	// /proc/1/cmdline: 以 \0 分隔的命令行参数
	data, err := os.ReadFile("/proc/1/cmdline")
	if err == nil {
		// 把 \0 替换成空格，方便阅读
		// 原始: "nginx\x00-g\x00daemon\x00off;\x00"
		// 转换: "nginx -g daemon off;"
		r.InitCmdline = strings.ReplaceAll(
			strings.TrimRight(string(data), "\x00"),
			"\x00", " ",
		)
	}

	// /proc/1/exe: 符号链接指向可执行文件的实际路径
	r.InitExe = readlinkSafe("/proc/1/exe")
}

// findSockets 探测容器内挂载的运行时 socket
//
// 为什么 socket 这么重要?
//
// Docker socket (/var/run/docker.sock) 挂进容器 = 命中了直接逃逸:
//  1. 通过 socket 调 Docker API
//  2. 创建一个新的特权容器，挂载宿主根目录 /
//  3. 在新容器里操作宿主文件系统
//  4. 逃逸完成
//
// containerd socket 同理，但用 gRPC 协议，更复杂
//
// 这是最"低技术"的逃逸方式——不需要任何内核漏洞
// 只需要运维犯了一个"把 socket 挂进去"的错误
func findSockets(r *RuntimeInfo) {
	// 常见 socket 路径
	// 不同运行时、不同系统的路径不同，都列出来
	candidates := []struct {
		path string
		name string
	}{
		{"/var/run/docker.sock", "docker"},
		{"/run/docker.sock", "docker"},
		{"/var/run/containerd/containerd.sock", "containerd"},
		{"/run/containerd/containerd.sock", "containerd"},
		{"/run/containerd/containerd-shim.sock", "containerd-shim"},
		{"/var/run/crio/crio.sock", "cri-o"},
		{"/run/crio/crio.sock", "cri-o"},
		{"/var/run/podman/podman.sock", "podman"},
		{"/run/podman/podman.sock", "podman"},
	}

	for _, s := range candidates {
		if fileExists(s.path) {
			r.RuntimeSockets = append(r.RuntimeSockets, s.path)
			if s.name == "docker" {
				r.DockerSocket = true
			}
		}
	}
}

// detectStorageDriver 从挂载信息推断存储驱动
//
// 存储驱动影响什么?
//
//	overlay2:     HostPath 在 /var/lib/docker/overlay2/<id>/
//	devicemapper: HostPath 在 /dev/mapper/docker-*  (设备级操作)
//	aufs:         HostPath 在 /var/lib/docker/aufs/ (旧版)
//
// 不同驱动的 HostPath 结构不同，影响 release_agent payload 的路径
func detectStorageDriver(r *RuntimeInfo) {
	// 从 /proc/self/mountinfo 找存储驱动线索
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return
	}

	content := string(data)

	// overlay2 检测: mountinfo 里有 "overlay / ..." 且有 "upperdir="
	if strings.Contains(content, "overlay") &&
		strings.Contains(content, "upperdir=") {
		r.StorageDriver = "overlay2"
		return
	}

	// devicemapper 检测: 有 /dev/mapper/ 设备
	if strings.Contains(content, "/dev/mapper/docker") {
		r.StorageDriver = "devicemapper"
		return
	}

	// aufs 检测
	if strings.Contains(content, "aufs") {
		r.StorageDriver = "aufs"
		return
	}

	// btrfs 检测
	if strings.Contains(content, "/var/lib/docker/btrfs") {
		r.StorageDriver = "btrfs"
		return
	}

	r.StorageDriver = "unknown"
}

// detectHostPath 探测容器在宿主文件系统上的绝对路径
//
// 为什么这是最关键的函数?
//
// release_agent 逃逸的完整链路:
//  1. 容器内写 payload 脚本 → /cmd
//  2. 告诉宿主 "请执行这个脚本"
//  3. 告诉宿主的路径必须是宿主文件系统上的绝对路径
//  4. 容器内看到的 /cmd 在宿主上实际是:
//     /var/lib/docker/overlay2/<容器ID>/diff/cmd
//  5. 如果不知道这个宿主路径 → 没法写 release_agent → 逃逸失败
//
// 探测方法有优先级:
//
//	方法1 (最准): 从 overlay mountinfo 里拿 upperdir
//	方法2 (准):   从 /etc/mtab 里找
//	方法3 (推测): 从 cgroup 路径提取容器 ID → 拼路径
//	方法4 (兜底): 都拿不到就留空，攻击时用 PID 爆破
func detectHostPath(r *RuntimeInfo) {
	// 先试方法1: 从 mountinfo 解析 overlay 的 upperdir
	if r.StorageDriver == "overlay2" {
		if path := parseHostPathFromMountinfo(); path != "" {
			r.HostPath = path
			return
		}
	}

	// 方法2: 从 /etc/mtab 找
	if path := parseHostPathFromMtab(); path != "" {
		r.HostPath = path
		return
	}

	// 方法3: 从 cgroup 路径推断
	//   /proc/1/cgroup 里有容器 ID
	//   拼上 /var/lib/docker/overlay2/ 就是宿主路径
	if path := parseHostPathFromCgroup(); path != "" {
		r.HostPath = path
		return
	}

	// 方法4: 留空，后面攻击时用 PID 爆破
	// 参考 release_agent.go Version 3
	r.HostPath = ""
}

// parseHostPathFromMountinfo 从 /proc/self/mountinfo 提取 HostPath
//
// mountinfo 里 overlay 挂载行的样子:
//
//	36 35 0:32 / / rw,relatime shared:1 - overlay overlay rw,
//	  lowerdir=/var/lib/docker/overlay2/l/XXX:...,
//	  upperdir=/var/lib/docker/overlay2/<容器ID>/diff,
//	  workdir=/var/lib/docker/overlay2/<容器ID>/work
//
// 我们要的是 upperdir，然后去掉末尾的 "/diff" 就是容器在宿主上的根路径
func parseHostPathFromMountinfo() string {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "overlay") {
			continue
		}

		// 找 upperdir=xxx
		re := regexp.MustCompile(`upperdir=([^,\s]+)`)
		if m := re.FindStringSubmatch(line); len(m) > 1 {
			upperDir := m[1]
			// upperdir = /var/lib/docker/overlay2/<ID>/diff
			// 我们要的 HostPath = /var/lib/docker/overlay2/<ID>
			// 去掉末尾的 "/diff"
			if strings.HasSuffix(upperDir, "/diff") {
				return strings.TrimSuffix(upperDir, "/diff")
			}
			// 有的系统不以 /diff 结尾，就直接用
			return upperDir
		}
	}
	return ""
}

// parseHostPathFromMtab 从 /etc/mtab 提取
// 某些系统 /etc/mtab 是 /proc/self/mountinfo 的软链接
// 有的是独立文件，格式略有不同
func parseHostPathFromMtab() string {
	// /etc/mtab 可能是软链到 /proc/self/mountinfo
	// 也可能是独立文件，格式: overlay / overlay rw,...
	// 逻辑和 mountinfo 一样
	data, err := os.ReadFile("/etc/mtab")
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "overlay") {
			continue
		}
		re := regexp.MustCompile(`upperdir=([^,\s]+)`)
		if m := re.FindStringSubmatch(line); len(m) > 1 {
			upperDir := m[1]
			if strings.HasSuffix(upperDir, "/diff") {
				return strings.TrimSuffix(upperDir, "/diff")
			}
			return upperDir
		}
	}
	return ""
}

// parseHostPathFromCgroup 从 cgroup 路径推断容器 ID
//
// /proc/1/cgroup 里的路径类似:
//
//	12:memory:/docker/<容器ID>
//	11:cpuset:/docker/<容器ID>
//	10:blkio:/docker/<容器ID>
//
// 从路径里提取容器 ID，拼上 /var/lib/docker/overlay2/
// 缺点: 这个路径不一定是对的(overlay2 的目录名不一定是容器 ID)
// 但作为一个猜测值，有总比没有好
func parseHostPathFromCgroup() string {
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return ""
	}

	// 匹配 docker/<容器ID> 格式
	re := regexp.MustCompile(`/docker/([0-9a-f]{64})`)
	if m := re.FindStringSubmatch(string(data)); len(m) > 1 {
		return "/var/lib/docker/overlay2/" + m[1]
	}

	// 匹配 docker-<容器ID>.scope 格式 (systemd cgroup 驱动)
	re2 := regexp.MustCompile(`/docker-([0-9a-f]{64})\.scope`)
	if m := re2.FindStringSubmatch(string(data)); len(m) > 1 {
		return "/var/lib/docker/overlay2/" + m[1]
	}

	return ""
}

// leakSensitiveEnv 检查容器环境变量中的敏感信息
//
// 很多开发者把密钥、密码直接写在环境变量里:
//
//	MYSQL_PASSWORD=xxx
//	AWS_SECRET_ACCESS_KEY=xxx
//	KUBERNETES_SERVICE_HOST=xxx (K8s API 地址)
//	DOCKER_HOST=tcp://xxx:2375 (远程 Docker API)
//
// 这些信息可以用于:
//   - 横向移动 (访问数据库、云服务)
//   - 逃逸后的进一步攻击
//   - 判断容器是否在 K8s 集群中
func leakSensitiveEnv(r *RuntimeInfo) {
	sensitivePrefixes := []string{
		"MYSQL_", "POSTGRES_", "REDIS_", "MONGO_",
		"AWS_SECRET_", "AWS_ACCESS_KEY",
		"GITLAB_TOKEN", "GITHUB_TOKEN",
		"KUBERNETES_", "K8S_",
		"DOCKER_HOST", "DOCKER_CERT_PATH",
		"DB_PASSWORD", "DB_SECRET",
		"SECRET_", "PRIVATE_KEY",
	}

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := parts[1]

		for _, prefix := range sensitivePrefixes {
			if strings.HasPrefix(strings.ToUpper(key), prefix) {
				// 只记录 key，不记录 value(避免泄露到报告)
				// 但 value 保留在结构体里供后续攻击模块使用
				r.EnvLeaks[key] = value
			}
		}
	}
}
