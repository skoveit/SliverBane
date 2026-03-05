package handler

import (
	"fmt"
	"math/rand"
	"strings"

	"sliverbane/internal/engine/identity"
	"sliverbane/protobuf/sliverpb"
)

// NetInfo generates realistic network information per session.
type NetInfo struct {
	interfaces []*sliverpb.NetInterface
	id         *identity.Identity
}

// NewNetInfo builds consistent network interfaces for the session.
func NewNetInfo(id *identity.Identity) *NetInfo {
	n := &NetInfo{id: id}
	if strings.ToLower(id.OS) == "windows" {
		n.buildWindows()
	} else {
		n.buildLinux()
	}
	return n
}

// HandleIfconfig returns the Ifconfig protobuf response.
func (n *NetInfo) HandleIfconfig() *sliverpb.Ifconfig {
	return &sliverpb.Ifconfig{
		NetInterfaces: n.interfaces,
		Response:      &sliverpb.Response{},
	}
}

// HandleNetstat returns a realistic Netstat protobuf response.
func (n *NetInfo) HandleNetstat(req *sliverpb.NetstatReq) *sliverpb.Netstat {
	entries := n.buildNetstat(req)
	return &sliverpb.Netstat{
		Entries:  entries,
		Response: &sliverpb.Response{},
	}
}

func (n *NetInfo) buildLinux() {
	n.interfaces = []*sliverpb.NetInterface{
		{
			Index:       1,
			Name:        "lo",
			MAC:         "00:00:00:00:00:00",
			IPAddresses: []string{"127.0.0.1/8", "::1/128"},
		},
		{
			Index:       2,
			Name:        "eth0",
			MAC:         n.id.MAC,
			IPAddresses: []string{n.id.IP + "/24", "fe80::" + fmt.Sprintf("%x:%xff:fe%x:%x", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)) + "/64"},
		},
	}
	// Optionally add docker0
	if rand.Intn(3) == 0 {
		n.interfaces = append(n.interfaces, &sliverpb.NetInterface{
			Index:       3,
			Name:        "docker0",
			MAC:         fmt.Sprintf("02:42:%02x:%02x:%02x:%02x", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)),
			IPAddresses: []string{"172.17.0.1/16"},
		})
	}
}

func (n *NetInfo) buildWindows() {
	n.interfaces = []*sliverpb.NetInterface{
		{
			Index:       1,
			Name:        "Loopback Pseudo-Interface 1",
			MAC:         "",
			IPAddresses: []string{"127.0.0.1/8", "::1/128"},
		},
		{
			Index:       6,
			Name:        "Ethernet",
			MAC:         n.id.MAC,
			IPAddresses: []string{n.id.IP + "/24", "fe80::" + fmt.Sprintf("%x:%xff:fe%x:%x", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)) + "/64"},
		},
	}
	// Optionally add vEthernet (WSL)
	if rand.Intn(3) == 0 {
		n.interfaces = append(n.interfaces, &sliverpb.NetInterface{
			Index:       12,
			Name:        "vEthernet (WSL)",
			MAC:         fmt.Sprintf("00:15:5D:%02x:%02x:%02x", rand.Intn(256), rand.Intn(256), rand.Intn(256)),
			IPAddresses: []string{"172.28.0.1/20"},
		})
	}
}

func (n *NetInfo) buildNetstat(req *sliverpb.NetstatReq) []*sliverpb.SockTabEntry {
	var entries []*sliverpb.SockTabEntry

	// LISTEN ports — common services
	listenPorts := []struct {
		port uint32
		name string
	}{
		{22, "sshd"},
		{80, "nginx"},
		{443, "nginx"},
		{3306, "mysqld"},
		{5432, "postgres"},
		{8080, "java"},
		{6379, "redis-server"},
		{27017, "mongod"},
	}
	if strings.ToLower(n.id.OS) == "windows" {
		listenPorts = []struct {
			port uint32
			name string
		}{
			{135, "svchost.exe"},
			{445, "System"},
			{3389, "svchost.exe"},
			{5985, "svchost.exe"},
			{80, "httpd.exe"},
			{443, "httpd.exe"},
			{1433, "sqlservr.exe"},
		}
	}

	for _, lp := range listenPorts {
		if rand.Intn(3) == 0 { // Don't show all — looks more natural
			continue
		}
		entries = append(entries, &sliverpb.SockTabEntry{
			LocalAddr:  &sliverpb.SockTabEntry_SockAddr{Ip: "0.0.0.0", Port: lp.port},
			RemoteAddr: &sliverpb.SockTabEntry_SockAddr{Ip: "0.0.0.0", Port: 0},
			SkState:    "LISTEN",
			UID:        0,
			Process:    &sliverpb.Process{Pid: int32(rand.Intn(30000) + 200), Executable: lp.name},
			Protocol:   "tcp",
		})
	}

	// ESTABLISHED connections
	estCount := 3 + rand.Intn(8)
	for i := 0; i < estCount; i++ {
		remoteIP := fmt.Sprintf("%d.%d.%d.%d", rand.Intn(224)+1, rand.Intn(256), rand.Intn(256), rand.Intn(254)+1)
		remotePorts := []uint32{443, 80, 8443, 993, 587, 53, 5228}
		entries = append(entries, &sliverpb.SockTabEntry{
			LocalAddr:  &sliverpb.SockTabEntry_SockAddr{Ip: n.id.IP, Port: uint32(30000 + rand.Intn(35000))},
			RemoteAddr: &sliverpb.SockTabEntry_SockAddr{Ip: remoteIP, Port: remotePorts[rand.Intn(len(remotePorts))]},
			SkState:    "ESTABLISHED",
			UID:        uint32(rand.Intn(2000)),
			Process:    &sliverpb.Process{Pid: int32(rand.Intn(30000) + 500), Executable: "chrome"},
			Protocol:   "tcp",
		})
	}

	// TIME_WAIT (recent closed connections)
	for i := 0; i < rand.Intn(5); i++ {
		entries = append(entries, &sliverpb.SockTabEntry{
			LocalAddr:  &sliverpb.SockTabEntry_SockAddr{Ip: n.id.IP, Port: uint32(30000 + rand.Intn(35000))},
			RemoteAddr: &sliverpb.SockTabEntry_SockAddr{Ip: fmt.Sprintf("%d.%d.%d.%d", rand.Intn(224)+1, rand.Intn(256), rand.Intn(256), rand.Intn(254)+1), Port: 443},
			SkState:    "TIME_WAIT",
			Protocol:   "tcp",
		})
	}

	return entries
}
