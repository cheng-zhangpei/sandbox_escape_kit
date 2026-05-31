package recon

func Collect(target string) ReconResult {
	var result ReconResult
	result.Target = target

	switch target {
	case "host":
		result.Kernel = collectKernel()
		result.Runtime = collectRuntime()
		result.Namespace = collectNamespace()
		result.Cgroup = collectCgroup()
		result.Capability = collectCapability()
		result.Security = collectSecurity(result.Capability) // 依赖 capability
		result.Proc = collectProc()
		result.Network = collectNetwork()

	case "container":
		result.Kernel = collectKernel()
		result.Runtime = collectRuntime()
		result.Namespace = collectNamespace()
		result.Cgroup = collectCgroup()
		result.Capability = collectCapability()
		result.Filesystem = collectFilesystem()
		result.Security = collectSecurity(result.Capability) // 依赖 capability
		result.Proc = collectProc()
		result.Network = collectNetwork()
	}

	return result
}
