package recon

// Collect 执行全部采集, 返回 ReconResult
// 三个阶段之间的接口是数据结构, 这里产出的就是 Analyze 阶段的输入
func Collect() ReconResult {
	var result ReconResult

	result.Kernel = collectKernel()
	// 后续逐个模块添加:
	// result.Runtime = collectRuntime()
	// result.Namespace = collectNamespace()
	// result.Cgroup = collectCgroup()
	// result.Capability = collectCapability()
	// result.Filesystem = collectFilesystem()
	// result.Proc = collectProc()
	// result.Security = collectSecurity()
	// result.Network = collectNetwork()

	return result
}
