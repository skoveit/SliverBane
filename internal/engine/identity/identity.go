package identity

import (
	"fmt"
	"math/rand"
	"strings"
)

// Identity holds all the generated attributes for a single session.
type Identity struct {
	Hostname string
	Username string
	Uid      string
	Gid      string
	OS       string
	Arch     string
	Pid      int32
	Filename string
	Version  string
	Locale   string
	MAC      string
	IP       string

	// Internal fields used by other subsystems
	HomeDir string
}

// Generate creates a realistic, randomized Identity for the given OS type.
func Generate(osType string) *Identity {
	osType = strings.ToLower(osType)
	id := &Identity{
		OS:     osType,
		Arch:   "amd64",
		Locale: pickLocale(),
	}

	if osType == "windows" {
		id.generateWindows()
	} else {
		id.generateLinux()
	}

	id.MAC = generateMAC()
	id.IP = generateIP()
	id.Version = "1.5.42"

	return id
}

// ─── Linux ───────────────────────────────────────────────────────────────────

var linuxHostnames = []string{
	"srv-web-%02d", "db-primary-%02d", "app-node-%02d",
	"proxy-edge-%02d", "monitor-%02d", "ci-runner-%02d",
	"k8s-worker-%02d", "vault-%02d", "dns-%02d",
	"backup-%02d", "log-collector-%02d", "dev-box-%02d",
	"staging-%02d", "prod-api-%02d", "bastion-%02d",
}

var linuxUsers = []string{
	"root", "admin", "deploy", "www-data", "ubuntu",
	"svc_monitor", "jenkins", "postgres", "nginx", "ansible",
	"devops", "backup", "ec2-user",
}

var linuxProcessNames = []string{
	"/usr/bin/python3", "/usr/sbin/sshd", "/usr/local/bin/node",
	"/opt/app/server", "/usr/bin/ruby", "/usr/sbin/cron",
	"/usr/bin/curl", "/tmp/.cache/update",
}

func (id *Identity) generateLinux() {
	pattern := linuxHostnames[rand.Intn(len(linuxHostnames))]
	id.Hostname = fmt.Sprintf(pattern, rand.Intn(50)+1)
	id.Username = linuxUsers[rand.Intn(len(linuxUsers))]
	id.Uid = fmt.Sprintf("%d", 1000+rand.Intn(9000))
	id.Gid = id.Uid
	if id.Username == "root" {
		id.Uid = "0"
		id.Gid = "0"
	}
	id.Pid = int32(1000 + rand.Intn(31000))
	id.Filename = linuxProcessNames[rand.Intn(len(linuxProcessNames))]
	id.HomeDir = "/home/" + id.Username
	if id.Username == "root" {
		id.HomeDir = "/root"
	}
}

// ─── Windows ─────────────────────────────────────────────────────────────────

var windowsHostnames = []string{
	"DESKTOP-%s", "WS-PROD-%04d", "DC-NYC-%02d",
	"SRV-DB-%s", "PC-%s", "LAPTOP-%s",
	"WIN-DEV-%02d", "FS-BACKUP-%02d", "EX-MAIL-%02d",
	"RDS-APP-%02d", "WEB-%02d", "SQL-%02d",
}

var windowsUsers = []string{
	"Administrator", "admin", "john.doe", "jane.smith",
	"svc_backup", "svc_sql", "SYSTEM", "IIS_IUSRS",
	"DefaultAccount", "Mike.Johnson", "sarah.chen",
	"helpdesk", "developer",
}

var windowsProcessNames = []string{
	"svchost.exe", "explorer.exe", "chrome.exe", "Teams.exe",
	"Outlook.exe", "powershell.exe", "RuntimeBroker.exe",
	"SearchHost.exe", "update.exe", "SecurityHealthSystray.exe",
}

func randomAlphaNum(n int) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func (id *Identity) generateWindows() {
	idx := rand.Intn(len(windowsHostnames))
	pattern := windowsHostnames[idx]
	switch {
	case strings.Contains(pattern, "%s"):
		id.Hostname = fmt.Sprintf(pattern, randomAlphaNum(7))
	case strings.Contains(pattern, "%04d"):
		id.Hostname = fmt.Sprintf(pattern, rand.Intn(9999))
	default:
		id.Hostname = fmt.Sprintf(pattern, rand.Intn(50)+1)
	}
	id.Username = windowsUsers[rand.Intn(len(windowsUsers))]
	id.Uid = ""
	id.Gid = ""
	id.Pid = int32(1000 + rand.Intn(39000))
	id.Filename = windowsProcessNames[rand.Intn(len(windowsProcessNames))]
	if id.Username == "SYSTEM" || id.Username == "Administrator" {
		id.HomeDir = `C:\Users\` + id.Username
	} else {
		id.HomeDir = `C:\Users\` + id.Username
	}
}

// ─── Shared ──────────────────────────────────────────────────────────────────

// OUI prefixes from common device manufacturers
var ouiPrefixes = []string{
	"00:50:56", // VMware
	"00:0C:29", // VMware
	"08:00:27", // VirtualBox
	"52:54:00", // QEMU/KVM
	"00:15:5D", // Hyper-V
	"00:1A:2B", // Ayecom
	"D4:BE:D9", // Dell
	"3C:22:FB", // Apple
	"F8:75:A4", // ASUS
	"48:2C:6A", // Cisco Meraki
	"00:25:B5", // Cisco
}

func generateMAC() string {
	prefix := ouiPrefixes[rand.Intn(len(ouiPrefixes))]
	return fmt.Sprintf("%s:%02x:%02x:%02x", prefix,
		rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

func generateIP() string {
	// Common internal subnets
	subnets := []string{
		"10.0.%d.%d",
		"10.1.%d.%d",
		"10.10.%d.%d",
		"172.16.%d.%d",
		"172.17.%d.%d",
		"192.168.1.%d",
		"192.168.10.%d",
		"192.168.100.%d",
	}
	pattern := subnets[rand.Intn(len(subnets))]
	count := strings.Count(pattern, "%d")
	switch count {
	case 2:
		return fmt.Sprintf(pattern, rand.Intn(255)+1, rand.Intn(254)+1)
	default:
		return fmt.Sprintf(pattern, rand.Intn(254)+1)
	}
}

var locales = []string{
	"en-US", "en-US", "en-US", "en-US", // weight towards en-US
	"en-GB", "de-DE", "fr-FR", "es-ES", "ja-JP", "zh-CN",
	"pt-BR", "ko-KR", "it-IT", "nl-NL",
}

func pickLocale() string {
	return locales[rand.Intn(len(locales))]
}
