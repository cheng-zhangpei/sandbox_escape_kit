package recon

import (
	"bufio"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func collectNetwork() NetworkInfo {
	info := NetworkInfo{}

	info.Mode = detectNetworkMode()
	info.Interfaces = getInterfaces()
	info.GatewayIP = detectGateway()
	info.ListeningPorts = detectListeningPorts()
	info.K8sTokenFound = detectK8s()

	return info
}

func detectNetworkMode() string {
	// 容器内如果能看到 docker0 或宿主的网络接口, 大概率是 host 模式
	for _, iface := range []string{"docker0", "br0", "virbr0"} {
		if _, err := net.InterfaceByName(iface); err == nil {
			return "host"
		}
	}
	// 看默认路由接口
	data, _ := os.ReadFile("/proc/net/route")
	if strings.Contains(string(data), "eth0") {
		return "bridge"
	}
	return "unknown"
}

func getInterfaces() []NetInterface {
	var result []NetInterface
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		ni := NetInterface{Name: iface.Name, MAC: iface.HardwareAddr.String()}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ni.IPs = append(ni.IPs, a.String())
		}
		result = append(result, ni)
	}
	return result
}

func detectGateway() string {
	f, _ := os.Open("/proc/net/route")
	if f == nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[1] == "00000000" {
			// gateway 是小端序 hex
			gw := fields[2]
			if len(gw) == 8 {
				b, _ := strconv.ParseUint(gw[6:8], 16, 8)
				c, _ := strconv.ParseUint(gw[4:6], 16, 8)
				d, _ := strconv.ParseUint(gw[2:4], 16, 8)
				e, _ := strconv.ParseUint(gw[0:2], 16, 8)
				return net.IPv4(byte(b), byte(c), byte(d), byte(e)).String()
			}
		}
	}
	return ""
}

func detectListeningPorts() []Port {
	var ports []Port
	f, _ := os.Open("/proc/net/tcp")
	if f == nil {
		return ports
	}
	defer f.Close()

	re := regexp.MustCompile(`\s+\d+:\s+([0-9A-F]+):([0-9A-F]+)\s+`)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		m := re.FindStringSubmatch(scanner.Text())
		if len(m) >= 3 && m[1] != "00000000" {
			port, _ := strconv.ParseInt(m[2], 16, 64)
			if port > 0 {
				ports = append(ports, Port{Protocol: "tcp", Port: int(port), Addr: "0.0.0.0"})
			}
		}
	}
	return ports
}

func detectK8s() bool {
	// K8s service account token
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	return false
}
