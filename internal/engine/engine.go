package engine

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"sliverbane/internal/config"
	"sliverbane/internal/engine/dos"
	"sliverbane/internal/engine/handler"
	"sliverbane/internal/engine/identity"
	"sliverbane/internal/engine/vfs"
	"sliverbane/internal/protocol"
	"sliverbane/internal/transport"
	"sliverbane/protobuf/sliverpb"

	"github.com/google/uuid"
	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"
)

// ─── Session Manager ─────────────────────────────────────────────────────────

type SessionInfo struct {
	ID       int
	Name     string
	Hostname string
	OS       string
	IP       string
	Status   string
	LastTick time.Time
}

type SessionManager struct {
	Mu       sync.RWMutex
	Sessions map[int]*SessionInfo
	Logs     chan string
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		Sessions: make(map[int]*SessionInfo),
		Logs:     make(chan string, 1000),
	}
}

func (sm *SessionManager) Log(msg string) {
	formatted := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
	select {
	case sm.Logs <- formatted:
	default:
	}
}

// ─── Engine ──────────────────────────────────────────────────────────────────

type Engine struct {
	Profile   *config.Profile
	TLSConfig *tls.Config
	EnvKey    *protocol.EnvelopeKey
	TargetURL string
	Manager   *SessionManager
}

func NewEngine(profile *config.Profile, target string, manager *SessionManager) (*Engine, error) {
	cert, err := tls.LoadX509KeyPair(profile.CertPath, profile.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	envKey, err := protocol.DeriveEnvelopeKey(profile.AgeKey)
	if err != nil {
		return nil, fmt.Errorf("derive envelope key: %w", err)
	}

	return &Engine{
		Profile:   profile,
		TLSConfig: tlsConfig,
		EnvKey:    envKey,
		TargetURL: target,
		Manager:   manager,
	}, nil
}

func (e *Engine) RunAttack(attackName string) error {
	attack, exists := dos.Registry[attackName]
	if !exists {
		return fmt.Errorf("attack '%s' not found", attackName)
	}

	t := transport.NewMTLS()
	conn, err := t.Connect(e.TargetURL, e.TLSConfig)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	session, err := protocol.SetupYamux(conn)
	if err != nil {
		return fmt.Errorf("yamux setup failed: %w", err)
	}
	defer session.Close()

	return attack.Execute(session, e.EnvKey)
}

func (e *Engine) Spawn(count int, startID int) {
	for i := 0; i < count; i++ {
		id := startID + i
		// Stagger connections to avoid suspicious burst
		go func(sessionID int) {
			jitter := time.Duration(rand.Intn(3000)) * time.Millisecond
			time.Sleep(jitter)
			e.runSession(sessionID)
		}(id)
	}
}

// ─── Session Lifecycle ───────────────────────────────────────────────────────

func (e *Engine) runSession(id int) {
	// Determine OS from profile hints
	osType := "linux"
	if strings.Contains(strings.ToLower(e.Profile.Name), "win") {
		osType = "windows"
	}

	// Generate unique identity
	ident := identity.Generate(osType)

	info := &SessionInfo{
		ID:       id,
		Name:     ident.Hostname,
		Hostname: ident.Hostname,
		OS:       ident.OS,
		IP:       ident.IP,
		Status:   "Connecting",
	}
	e.Manager.Mu.Lock()
	e.Manager.Sessions[id] = info
	e.Manager.Mu.Unlock()

	e.Manager.Log(fmt.Sprintf("Session %d connecting to %s as %s@%s",
		id, e.TargetURL, ident.Username, ident.Hostname))

	// Connect
	t := transport.NewMTLS()
	conn, err := t.Connect(e.TargetURL, e.TLSConfig)
	if err != nil {
		info.Status = "Failed: Connection"
		e.Manager.Log(fmt.Sprintf("Session %d connection failed: %v", id, err))
		return
	}
	defer conn.Close()

	session, err := protocol.SetupYamux(conn)
	if err != nil {
		info.Status = "Failed: Yamux"
		e.Manager.Log(fmt.Sprintf("Session %d yamux failed: %v", id, err))
		return
	}
	defer session.Close()

	// Build subsystems
	fs := vfs.NewSessionFS(ident)
	procTable := handler.NewProcessTable(ident)
	netInfo := handler.NewNetInfo(ident)
	envTable := handler.NewEnvTable(ident)
	router := handler.NewRouter()

	// Register
	stream, err := session.Open()
	if err != nil {
		info.Status = "Failed: Registration"
		return
	}

	register := &sliverpb.Register{
		Name:              ident.Hostname,
		Hostname:          ident.Hostname,
		Uuid:              uuid.New().String(),
		Username:          ident.Username,
		Uid:               ident.Uid,
		Gid:               ident.Gid,
		Os:                ident.OS,
		Arch:              ident.Arch,
		Pid:               ident.Pid,
		Filename:          ident.Filename,
		ActiveC2:          fmt.Sprintf("mtls://%s", e.TargetURL),
		Version:           ident.Version,
		ReconnectInterval: 60,
		Locale:            ident.Locale,
	}

	regData, _ := proto.Marshal(register)
	protocol.WriteEnvelope(stream, &sliverpb.Envelope{Type: sliverpb.MsgRegister, Data: regData}, e.EnvKey)
	stream.Close()

	info.Status = "Active"
	info.LastTick = time.Now()
	e.Manager.Log(fmt.Sprintf("Session %d registered (%s@%s OS:%s IP:%s PID:%d)",
		id, ident.Username, ident.Hostname, ident.OS, ident.IP, ident.Pid))

	// Keepalive goroutine
	stop := make(chan struct{})
	defer close(stop)

	go func() {
		interval := 25 + rand.Intn(15) // 25-40s, not a fixed 30s
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				pStream, err := session.Open()
				if err != nil {
					return
				}
				protocol.WriteEnvelope(pStream, &sliverpb.Envelope{Type: sliverpb.MsgPing}, e.EnvKey)
				pStream.Close()
				e.Manager.Mu.Lock()
				info.LastTick = time.Now()
				e.Manager.Mu.Unlock()
			case <-stop:
				return
			}
		}
	}()

	// Task handler loop
	for {
		tStream, err := session.Accept()
		if err != nil {
			info.Status = "Disconnected"
			e.Manager.Log(fmt.Sprintf("Session %d disconnected", id))
			return
		}

		go func(s net.Conn) {
			defer s.Close()

			env, err := protocol.ReadEnvelope(s)
			if err != nil {
				return
			}

			// Response delay jitter: 50-500ms to simulate real implant
			jitter := time.Duration(50+rand.Intn(450)) * time.Millisecond
			time.Sleep(jitter)

			e.Manager.Log(fmt.Sprintf("Session %d task type=%d", id, env.Type))

			var resp proto.Message
			var respMsgType uint32

			switch env.Type {

			// ── Filesystem ──────────────────────────────────────────
			case sliverpb.MsgLsReq:
				req := &sliverpb.LsReq{}
				proto.Unmarshal(env.Data, req)
				resp = fs.HandleLs(req)
				respMsgType = sliverpb.MsgLs

			case sliverpb.MsgCdReq:
				req := &sliverpb.CdReq{}
				proto.Unmarshal(env.Data, req)
				fs.HandleCd(req)
				resp = fs.HandlePwd()
				respMsgType = sliverpb.MsgPwd

			case sliverpb.MsgPwdReq:
				resp = fs.HandlePwd()
				respMsgType = sliverpb.MsgPwd

			case sliverpb.MsgDownloadReq:
				req := &sliverpb.DownloadReq{}
				proto.Unmarshal(env.Data, req)
				resp = fs.HandleDownload(req)
				respMsgType = sliverpb.MsgDownload

			case sliverpb.MsgUploadReq:
				req := &sliverpb.UploadReq{}
				proto.Unmarshal(env.Data, req)
				resp = fs.HandleUpload(req)
				respMsgType = sliverpb.MsgUpload

			case sliverpb.MsgRmReq:
				req := &sliverpb.RmReq{}
				proto.Unmarshal(env.Data, req)
				resp = fs.HandleRm(req)
				respMsgType = sliverpb.MsgRm

			case sliverpb.MsgMkdirReq:
				req := &sliverpb.MkdirReq{}
				proto.Unmarshal(env.Data, req)
				resp = fs.HandleMkdir(req)
				respMsgType = sliverpb.MsgMkdir

			case sliverpb.MsgMvReq:
				req := &sliverpb.MvReq{}
				proto.Unmarshal(env.Data, req)
				resp = &sliverpb.Mv{Src: req.Src, Dst: req.Dst, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgMv

			case sliverpb.MsgCpReq:
				req := &sliverpb.CpReq{}
				proto.Unmarshal(env.Data, req)
				resp = &sliverpb.Cp{Src: req.Src, Dst: req.Dst, BytesWritten: 0, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgCp

			case sliverpb.MsgChmodReq:
				req := &sliverpb.ChmodReq{}
				proto.Unmarshal(env.Data, req)
				resp = &sliverpb.Chmod{Path: req.Path, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgChmod

			case sliverpb.MsgChownReq:
				req := &sliverpb.ChownReq{}
				proto.Unmarshal(env.Data, req)
				resp = &sliverpb.Chown{Path: req.Path, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgChown

			case sliverpb.MsgChtimesReq:
				req := &sliverpb.ChtimesReq{}
				proto.Unmarshal(env.Data, req)
				resp = &sliverpb.Chtimes{Path: req.Path, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgChtimes

			// ── Process / System Info ────────────────────────────────
			case sliverpb.MsgPsReq:
				resp = procTable.HandlePs()
				respMsgType = sliverpb.MsgPs

			case sliverpb.MsgIfconfigReq:
				resp = netInfo.HandleIfconfig()
				respMsgType = sliverpb.MsgIfconfig

			case sliverpb.MsgNetstatReq:
				req := &sliverpb.NetstatReq{}
				proto.Unmarshal(env.Data, req)
				resp = netInfo.HandleNetstat(req)
				respMsgType = sliverpb.MsgNetstatReq // Sliver uses the req type for netstat response

			case sliverpb.MsgEnvReq:
				req := &sliverpb.EnvReq{}
				proto.Unmarshal(env.Data, req)
				resp = envTable.HandleEnv(req)
				respMsgType = sliverpb.MsgEnvInfo

			case sliverpb.MsgSetEnvReq:
				resp = &sliverpb.SetEnv{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgSetEnv

			case sliverpb.MsgUnsetEnvReq:
				resp = &sliverpb.UnsetEnv{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgUnsetEnvReq

			// ── Token / Whoami ───────────────────────────────────────
			case sliverpb.MsgCurrentTokenOwnerReq:
				output := ident.Username
				if ident.OS == "windows" {
					output = fmt.Sprintf("%s\\%s", ident.Hostname, ident.Username)
				}
				resp = &sliverpb.CurrentTokenOwner{Output: output, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgCurrentTokenOwner

			case sliverpb.MsgGetPrivsReq:
				resp = &sliverpb.Privileges{Info: "SeDebugPrivilege\nSeImpersonatePrivilege\nSeBackupPrivilege\n", Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgGetPrivsReq

			case sliverpb.MsgMakeTokenReq:
				resp = &sliverpb.MakeToken{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgMakeToken

			case sliverpb.MsgRevToSelfReq:
				resp = &sliverpb.RevToSelf{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgRevToSelf

			case sliverpb.MsgImpersonateReq:
				resp = &sliverpb.Impersonate{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgImpersonate

			// ── Execute ─────────────────────────────────────────────
			case sliverpb.MsgExecuteReq:
				req := &sliverpb.ExecuteReq{}
				proto.Unmarshal(env.Data, req)
				output := router.Route(fs, req.Path, req.Args)
				resp = &sliverpb.Execute{
					Stdout:   []byte(output),
					Status:   0,
					Pid:      uint32(rand.Intn(30000) + 1000),
					Response: &sliverpb.Response{},
				}
				respMsgType = sliverpb.MsgExecuteReq

			// ── Terminate ────────────────────────────────────────────
			case sliverpb.MsgTerminateReq:
				req := &sliverpb.TerminateReq{}
				proto.Unmarshal(env.Data, req)
				resp = &sliverpb.Terminate{Pid: req.Pid, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgTerminate

			// ── Screenshot (return 1x1 black PNG) ────────────────────
			case sliverpb.MsgScreenshotReq:
				resp = &sliverpb.Screenshot{Data: black1x1PNG(), Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgScreenshot

			// ── Reconfigure ──────────────────────────────────────────
			case sliverpb.MsgReconfigureReq:
				resp = &sliverpb.Reconfigure{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgReconfigure

			// ── Kill session (just ACK — session keeps running) ────────
			case sliverpb.MsgKillSessionReq:
				// Don't actually die, just acknowledge
				resp = &sliverpb.Response{}
				respMsgType = sliverpb.MsgKillSessionReq

			// ── Ping ─────────────────────────────────────────────────
			case sliverpb.MsgPing:
				req := &sliverpb.Ping{}
				proto.Unmarshal(env.Data, req)
				resp = &sliverpb.Ping{Nonce: req.Nonce + 1, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgPing

			// ── Extensions (stub — return empty) ─────────────────────
			case sliverpb.MsgListExtensionsReq:
				resp = &sliverpb.ListExtensions{Names: []string{}, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgListExtensionsReq

			case sliverpb.MsgRegisterExtensionReq:
				resp = &sliverpb.RegisterExtension{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgRegisterExtensionReq

			case sliverpb.MsgCallExtensionReq:
				resp = &sliverpb.CallExtension{Output: []byte{}, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgCallExtensionReq

			// ── Sideload / SpawnDll / ExecuteAssembly (stub) ─────────
			case sliverpb.MsgSideloadReq:
				resp = &sliverpb.Sideload{Result: "", Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgSideload

			case sliverpb.MsgSpawnDllReq:
				resp = &sliverpb.SpawnDll{Result: "", Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgSpawnDll

			case sliverpb.MsgExecuteAssemblyReq:
				resp = &sliverpb.ExecuteAssembly{Output: []byte{}, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgExecuteAssembly

			// ── Shell (deny — return error) ──────────────────────────
			case sliverpb.MsgShellReq:
				resp = &sliverpb.Shell{Response: &sliverpb.Response{Err: "operation not permitted"}}
				respMsgType = sliverpb.MsgShell

			// ── Process dump (return empty) ──────────────────────────
			case sliverpb.MsgProcessDumpReq:
				resp = &sliverpb.ProcessDump{Data: []byte{}, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgProcessDump

			// ── Task injection (stub ACK) ────────────────────────────
			case sliverpb.MsgTaskReq:
				resp = &sliverpb.Task{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgTaskReq

			// ── Registry (Windows stubs) ─────────────────────────────
			case sliverpb.MsgRegistryReadReq:
				resp = &sliverpb.RegistryRead{Value: "", Response: &sliverpb.Response{Err: "key not found"}}
				respMsgType = sliverpb.MsgRegistryReadReq

			case sliverpb.MsgRegistryWriteReq:
				resp = &sliverpb.RegistryWrite{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgRegistryWriteReq

			case sliverpb.MsgRegistryCreateKeyReq:
				resp = &sliverpb.RegistryCreateKey{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgRegistryCreateKeyReq

			case sliverpb.MsgRegistryDeleteKeyReq:
				resp = &sliverpb.RegistryDeleteKey{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgRegistryDeleteKeyReq

			case sliverpb.MsgRegistrySubKeysListReq:
				resp = &sliverpb.RegistrySubKeyList{Subkeys: []string{}, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgRegistrySubKeysListReq

			case sliverpb.MsgRegistryListValuesReq:
				resp = &sliverpb.RegistryValuesList{ValueNames: []string{}, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgRegistryListValuesReq

			// ── Mount ────────────────────────────────────────────────
			case sliverpb.MsgMountReq:
				resp = buildMountResponse(ident.OS)
				respMsgType = sliverpb.MsgMountReq

			// ── Grep ─────────────────────────────────────────────────
			case sliverpb.MsgGrepReq:
				resp = &sliverpb.Grep{Results: map[string]*sliverpb.GrepResultsForFile{}, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgGrepReq

			// ── SSH (stub) ───────────────────────────────────────────
			case sliverpb.MsgSSHCommandReq:
				resp = &sliverpb.SSHCommand{StdOut: []byte("Permission denied\n"), StdErr: []byte{}, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgSSHCommandReq

			// ── Pivots (stub) ────────────────────────────────────────
			case sliverpb.MsgPivotListenersReq:
				resp = &sliverpb.PivotListeners{Listeners: []*sliverpb.PivotListener{}, Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgPivotListeners

			// ── Services (stub) ──────────────────────────────────────
			case sliverpb.MsgStartServiceReq:
				resp = &sliverpb.ServiceInfo{Response: &sliverpb.Response{}}
				respMsgType = sliverpb.MsgStartService

			// ── Default: return UnknownMessageType ───────────────────
			default:
				e.Manager.Log(fmt.Sprintf("Session %d unhandled msg type %d — returning unknown", id, env.Type))
				resp = nil
				// Send empty envelope with UnknownMessageType flag
				data, _ := proto.Marshal(&sliverpb.Envelope{})
				unknownEnv := &sliverpb.Envelope{
					ID:                 env.ID,
					Type:               env.Type,
					Data:               data,
					UnknownMessageType: true,
				}
				rStream, err := session.Open()
				if err != nil {
					return
				}
				defer rStream.Close()
				protocol.WriteEnvelope(rStream, unknownEnv, e.EnvKey)
				return
			}

			if resp != nil {
				e.sendResponse(session, env.ID, respMsgType, resp)
			}
		}(tStream)
	}
}

func (e *Engine) sendResponse(session *yamux.Session, envID int64, msgType uint32, msg proto.Message) {
	data, err := proto.Marshal(msg)
	if err != nil {
		return
	}
	envelope := &sliverpb.Envelope{
		ID:   envID,
		Type: msgType,
		Data: data,
	}
	stream, err := session.Open()
	if err != nil {
		return
	}
	defer stream.Close()
	protocol.WriteEnvelope(stream, envelope, e.EnvKey)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// black1x1PNG returns a valid 1x1 black PNG image (67 bytes).
func black1x1PNG() []byte {
	return []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, // 8-bit RGB
		0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, // IDAT chunk
		0x08, 0xD7, 0x63, 0x60, 0x60, 0x60, 0x00, 0x00, // deflated black pixel
		0x00, 0x04, 0x00, 0x01, 0x27, 0x34, 0x27, 0x0A,
		0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND chunk
		0xAE, 0x42, 0x60, 0x82,
	}
}

func buildMountResponse(osType string) *sliverpb.Mount {
	if strings.ToLower(osType) == "windows" {
		return &sliverpb.Mount{
			Info: []*sliverpb.MountInfo{
				{
					VolumeName: `\\?\Volume{a1b2c3d4-0000-0000-0000-100000000000}\`,
					VolumeType: "Fixed",
					MountPoint: `C:\`,
					Label:      "OS",
					FileSystem: "NTFS",
					TotalSpace: 500 * 1024 * 1024 * 1024,
					FreeSpace:  200 * 1024 * 1024 * 1024,
					UsedSpace:  300 * 1024 * 1024 * 1024,
				},
			},
			Response: &sliverpb.Response{},
		}
	}
	return &sliverpb.Mount{
		Info: []*sliverpb.MountInfo{
			{
				VolumeName:   "/dev/sda1",
				VolumeType:   "disk",
				MountPoint:   "/",
				FileSystem:   "ext4",
				TotalSpace:   50 * 1024 * 1024 * 1024,
				FreeSpace:    20 * 1024 * 1024 * 1024,
				UsedSpace:    30 * 1024 * 1024 * 1024,
				MountOptions: "rw,relatime,errors=remount-ro",
			},
			{
				VolumeName:   "tmpfs",
				VolumeType:   "tmpfs",
				MountPoint:   "/tmp",
				FileSystem:   "tmpfs",
				TotalSpace:   4 * 1024 * 1024 * 1024,
				FreeSpace:    4 * 1024 * 1024 * 1024,
				MountOptions: "rw,nosuid,nodev",
			},
		},
		Response: &sliverpb.Response{},
	}
}
