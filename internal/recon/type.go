package recon

// ============================================================
// ReconResult — 采集引擎的最终输出，Analyze 阶段的输入
// ============================================================

type ReconResult struct {
	// 每一种info在这里都代表了一类的攻击面
	Target     string
	Kernel     KernelInfo
	Runtime    RuntimeInfo
	Namespace  NamespaceInfo
	Cgroup     CgroupInfo
	Capability CapabilityInfo
	Filesystem FilesystemInfo
	Proc       ProcInfo
	Security   SecurityInfo
	Network    NetworkInfo
}

// ============================================================
// Layer 1: 内核信息
// 攻击意义: 内核版本直接决定能匹配哪些 CVE
//   比如 5.15 以下要考虑 DirtyPipe, 5.17 以下要考虑 release_agent patch
// ============================================================

type KernelInfo struct {
	Version     [3]int          // 主版本.次版本.补丁, 方便做范围比较
	Release     string          // 完整版本字符串, 如 "5.15.0-91-generic"
	CompileDate string          // 从 /proc/version 提取的编译时间
	Arch        string          // "x86_64" 或 "aarch64" — IDV终端可能是ARM
	Modules     []string        // 已加载内核模块, 某些CVE依赖特定模块
	Cmdline     string          // 内核启动参数, 比如有 lockdown= 则限制更多
	ConfigFlags map[string]bool // CONFIG_USER_NS 等编译选项, 决定攻击面
}

// ============================================================
// Layer 1: 运行时信息
// 攻击意义: 运行时类型决定了特定的逃逸路径
//   比如 runc < 1.1.12 有 fd 泄漏 (CVE-2024-21626)
//   docker.sock 挂进来可以直接创建特权容器
// ============================================================

type RuntimeType int

const (
	RuntimeUnknown    RuntimeType = iota
	RuntimeDocker                 // /.dockerenv 存在
	RuntimeContainerd             // 直接用 containerd
	RuntimePodman                 // /run/.containerenv 存在
	RuntimeLXC
)

type RuntimeInfo struct {
	Type           RuntimeType
	Version        string            // 容器运行时版本
	RuncVersion    string            // runc 版本, CVE-2024-21626 需要 < 1.1.12
	InitCmdline    string            // /proc/1/cmdline, 看容器怎么启动的
	InitExe        string            // /proc/1/exe readlink
	RuntimeSockets []string          // 找到的运行时 socket 路径
	DockerSocket   bool              // /var/run/docker.sock 是否存在 — 这个发现了基本就是逃逸
	StorageDriver  string            // overlay2, devicemapper 等
	HostPath       string            // 容器在宿主上的绝对路径, release_agent 的关键
	EnvLeaks       map[string]string // 从环境变量泄露的敏感信息
}

// ============================================================
// Layer 3: Namespace 隔离
// 攻击意义: 共享 namespace = 直接攻击宿主
//
//	pid 共享 → ptrace 宿主进程
//	mnt 共享 → 直接写宿主文件
//	net 共享 → 访问宿主 localhost 服务
//
// ============================================================
// NsEntry 只存原始数据, 不做任何判断
type NsEntry struct {
	Name      string // "pid", "net", ...
	Inode     string // /proc/self/ns/X 的 inode (当前进程)
	InitInode string // /proc/1/ns/X 的 inode (PID 1)
	Available bool   // 内核是否支持这个 namespace
}

type NamespaceInfo struct {
	Entries       map[string]NsEntry // 采集到的 namespace 原始数据
	UserNsCreated bool               // 能否创建新 user namespace
}

// ============================================================
// Layer 3: Cgroup 信息
// 攻击意义: cgroup v1 release_agent 是最经典的容器逃逸
//   需要找到可写的子系统, 确定 notify_on_release 和 release_agent 的写权限
//   v2 没有 release_agent, 逃逸路径不同
// ============================================================

//type CgSubsystem struct {
//	Name                    string   // "memory", "cpu", "pids" 等
//	MountPath               string   // /sys/fs/cgroup/memory
//	SelfPath                string   // 容器在该子系统下的路径
//	ReleaseAgentExists      bool     // release_agent 文件是否存在
//	ReleaseAgentWritable    bool     // 能否写入 release_agent
//	NotifyOnReleaseWritable bool     // 能否写入 notify_on_release — 前提条件
//	CgroupProcsWritable     bool     // 能否写入 cgroup.procs — 触发逃逸的关键
//	SubDirs                 []string // 能否在该子系统下创建子目录
//}

type CgroupInfo struct {
	Version                int // 1 或 2
	Subsystems             map[string]CgSubsystem
	DevicesAllowWritable   bool   // cgroup v1 devices.allow 可写 → 挂载宿主磁盘
	SubtreeControlWritable bool   // cgroup v2 的 subtree_control
	UnifiedPath            string // v2 统一挂载点
}
type CgSubsystem struct {
	Name                    string   // "memory", "cpu", "pids" 等
	MountPath               string   // /sys/fs/cgroup/memory
	SelfPath                string   // 容器在该子系统下的路径
	ReleaseAgentExists      bool     // release_agent 文件是否存在
	ReleaseAgentWritable    bool     // 能否写入 release_agent
	NotifyOnReleaseWritable bool     // 能否写入 notify_on_release — 前提条件
	CgroupProcsWritable     bool     // 能否写入 cgroup.procs — 触发逃逸的关键
	SubDirs                 []string // 能否在该子系统下创建子目录
	SubtreeControlWritable  bool     // ← 加这行, cgroup v2 用
}

// ============================================================
// Layer 2: 权限与 Capability
// 攻击意义: CAP_SYS_ADMIN 基本等于容器逃逸门票
//   没有 CAP_SYS_ADMIN 时, 需要找 user namespace 绕路
//   root vs 非 root 的攻击面差距巨大
// ============================================================

type CapabilityInfo struct {
	Effective     uint64 // CapEff 原始值
	Bounding      uint64 // CapBnd
	Inheritable   uint64
	Permitted     uint64
	IsPrivileged  bool     // 全能力: 0000003fffffffff
	ActiveNames   []string // 激活的能力名称列表, 人类可读
	DangerousCaps []int    // 激活的危险 capability 的 bit 位号
	UID           int      // 当前用户
	GID           int
	EUID          int // effective UID, 判断是否有 setuid 生效
}

// ============================================================
// Layer 1+3: 文件系统
// 攻击意义: SUID 二进制可以直接提权
//   宿主根目录挂载进来 = 一键逃逸
//   overlay 的 upperdir 路径是 release_agent 的必备信息
// ============================================================

type MountEntry struct {
	Source     string // 设备/来源
	Target     string // 挂载点
	FSType     string // overlay, tmpfs, ext4
	Options    string // rw, ro
	IsReadOnly bool
	UpperDir   string // overlay upperdir — 定位 HostPath 的关键
	WorkDir    string // overlay workdir
	LowerDirs  []string
}

type SuidBinary struct {
	Path          string
	IsExploitable bool   // 是否在已知可利用列表 (GTFOBins)
	ExploitMethod string // 具体利用方式, 如 "nmap !sh"
}

type FilesystemInfo struct {
	Mounts           []MountEntry
	BlockDevices     []string // /dev/sd*, /dev/vd*
	DangerousDevices []string // /dev/mem, /dev/kmem, /dev/fuse
	SuidBinaries     []SuidBinary
	WritablePaths    []string // /etc/passwd, /proc/sys/ 等可写路径
	HostRootMounted  bool     // 宿主根目录是否挂载 — 最高危
}

// ============================================================
// Layer 2+3: /proc 相关
// 攻击意义:
//   core_pattern 可写 → 触发 coredump 在宿主执行任意命令
//   modprobe 可写 → 内核加载模块时执行任意命令
//   fd 泄漏 → CVE-2024-21626, 直接访问宿主文件系统
// ============================================================

type FdLeak struct {
	PID        int
	FD         int
	Target     string // readlink 得到的路径
	IsHostPath bool   // 是否指向宿主路径 (包含 docker, overlay2, containerd)
}

type ProcInfo struct {
	CorePatternWritable bool   // /proc/sys/kernel/core_pattern 可写?
	CorePatternValue    string // 当前值
	ModprobeWritable    bool   // /proc/sys/kernel/modprobe 可写?
	ModprobeValue       string
	HotplugWritable     bool // /proc/sys/kernel/hotplug
	SysrqWritable       bool
	Proc1RootReadable   bool // 能否读 /proc/1/root — 判断是否和宿主共享 pid ns
	Proc1RootContents   []string
	FdLeaks             []FdLeak // 泄漏的 fd 列表 — CVE-2024-21626
	VisibleHostPids     int      // 能看到多少宿主进程 — 判断 pid ns 共享程度
}

// ============================================================
// Layer 4: 安全策略
// 攻击意义: seccomp 过滤了哪些 syscall 直接决定攻击方案能不能执行
//   比如 mount 被 block → release_agent 就用不了
//   ptrace 被 block → pid namespace 共享也没法注入
// ============================================================

type SecurityInfo struct {
	SeccompMode      int             // 0=off, 1=strict, 2=filter
	AppArmorProfile  string          // "docker-default" 还是 "unconfined"
	SELinuxMode      string          // Enforcing, Permissive, Disabled
	ReadOnlyRootfs   bool            // 只读根文件系统
	NoNewPrivs       bool            // PR_SET_NO_NEW_PRIVS
	SyscallReachable map[string]bool // 实际 syscall 测试结果, key 是 syscall 名
	SyscallBlocked   map[string]bool
}

// ============================================================
// Layer 附加: 网络信息
// 从 Namespace 拆出来是因为信息量大
// 攻击意义: host 网络模式下可以直接访问宿主服务
//   找到 docker API 或 kubelet 就能横向
// ============================================================

type NetInterface struct {
	Name string
	IPs  []string
	MAC  string
}

type Port struct {
	Protocol string // "tcp", "udp"
	Port     int
	Addr     string
}

type Service struct {
	Name    string // 识别出的服务名
	Addr    string
	Port    int
	Details string
}

type NetworkInfo struct {
	Mode              string // "bridge", "host", "none"
	Interfaces        []NetInterface
	ListeningPorts    []Port
	GatewayIP         string
	ReachableServices []Service // 宿主/邻近容器可达的服务
	K8sTokenFound     bool
	K8sAPIServer      string
}
