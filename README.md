<p align="center">
  <img src="https://img.shields.io/badge/lang-Go-00ADD8?style=flat-square&logo=go" />
  <img src="https://img.shields.io/badge/target-Sliver%20C2-red?style=flat-square" />
  <img src="https://img.shields.io/badge/purpose-Red%20Team%20Hunting-C51A4A?style=flat-square" />
</p>

<p align="center">
<pre align="center">
   _____ _ _                ____                  
  / ____| (_)              |  _ \                 
 | (___ | |___   _____ _ __| |_) | __ _ _ __   ___ 
  \___ \| | \ \ / / _ \ '__|  _ < / _` | '_ \ / _ \
  ____) | | |\ V /  __/ |  | |_) | (_| | | | |  __/
 |_____/|_|_| \_/ \___|_|  |____/ \__,_|_| |_|\___|
</pre>
</p>


# SliverBane

**Counter-C2 framework built to attack Red Teams**. SliverBane connects to an active Sliver C2 server and spawns fake implant sessions that are indistinguishable from real ones. It serves as an active defense tool to burn the operator's time and pollute their database, a honeybot trap to gain intelligence on an attacker's intent and next moves, and a Proof Of Concept (PoC) for Denial of Service (DoS) attacks to completely shut down the C2 server.

## What It Does

SliverBane connects to a Sliver C2 server using stolen mTLS credentials and registers fake implant sessions. To the operator, these ghosts look identical to real compromised hosts:

| Capability | Details |
|---|---|
| **DoS Modules** | Pluggable attack modules for service disruption (nil-deref panic, OOM) |
| **Realistic Identity** | Corporate hostnames (`srv-web-03`, `DESKTOP-A7K9M2P`), OS-appropriate usernames, valid MAC/IP, randomized PIDs |
| **Rich Filesystem** | 150+ files on Linux, 100+ on Windows — `/etc/passwd`, `/proc/cpuinfo`, `C:\Windows\System32` DLLs, browser profiles, honeypot `passwords.txt` |
| **Proper Protocol** | 50+ Sliver message types handled with correct protobuf responses — `ps`, `ls`, `ifconfig`, `netstat`, `env`, `whoami`, `download`, `upload`, `screenshot`, and more |
| **Anti-Detection** | 50–500ms response jitter, randomized keepalive intervals, `UnknownMessageType` for unsupported commands (exactly what real implants do) |

---

## Denial of Service (DoS) Modules
SliverBane includes pluggable Denial of Service modules designed to disrupt target C2 infrastructure by exploiting known vulnerabilities in the Sliver server.

| Module | Description | Vulnerable Versions | CVE |
|--------|-------------|---------------------|-----|
| `nil` | Nil-pointer dereference panic during envelope parsing. | `<= v1.7.3` | **CVE-2026-29781** |
| `oom` | Out-of-Memory (OOM) crash via excessive length prefix allocation. | `<= v1.7.3` | N/A |

Run `dos list` to see available modules, and `dos run <module>` to deploy a payload.



---

## Quick Start

### Build

```bash
go build -o sliverbane ./cmd/ghost
```

### Configure

```bash
# Create a profile
sliverbane > create attacker op1 

# Set credentials
sliverbane [op1] > set mtls --cert implant.crt --key implant.key --age "AGE-SECRET-KEY-..."

# Set target
sliverbane [op1] > set target 10.0.0.5:8888
```

### Attack

```bash
# Spawn 5 fake sessions
sliverbane [op1] > run --count 5

# Or with target override
sliverbane [op1] > run --count 10 --target 10.0.0.5:8888
```

### Interactive Mode

```bash
./sliverbane

   _____ _ _                ____                  
  / ____| (_)              |  _ \                 
 | (___ | |___   _____ _ __| |_) | __ _ _ __   ___ 
  \___ \| | \ \ / / _ \ '__|  _ < / _` | '_ \ / _ \
  ____) | | |\ V /  __/ |  | |_) | (_| | | | |  __/
 |_____/|_|_| \_/ \___|_|  |____/ \__,_|_| |_|\___|

       Counter-C2 Deception Engine  v1.0
              ~ @Skove ~

sliverbane [op1] > run --count 3
sliverbane [op1] > report
sliverbane [op1] > monitor
```

---

## Commands

| Command | Description |
|---|---|
| `create attacker <name>` | Create a new attacker profile |
| `use <name>` | Switch active profile |
| `set mtls --cert --key --age` | Configure mTLS credentials |
| `set target <host:port>` | Set C2 target address |
| `run --count N [--target]` | Spawn N ghost sessions |
| `report` | Show active session summary |
| `monitor` | Live log stream |
| `profiles` | List profiles |
| `config` | Show active profile details |
| `dos list` | List available DoS modules |
| `dos run <name> [--target]` | Execute a DoS attack |

---

## What The Operator Sees

When an operator interacts with a ghost session, they get:

- **`sessions`** — A legitimate-looking implant with realistic hostname, OS, user, PID
- **`ls /etc`** — Full directory listing with proper file sizes, permissions, timestamps
- **`ps`** — Complete process tree (systemd→sshd→bash on Linux, System→services→svchost×15→explorer on Windows)
- **`ifconfig`** — Proper `NetInterface` protobuf entries with MAC addresses
- **`netstat`** — Realistic LISTEN/ESTABLISHED/TIME_WAIT socket entries
- **`env`** — Full environment variables (PATH, HOME, SSH_*, COMPUTERNAME, etc.)
- **`cat /etc/passwd`** — Realistic passwd file with the ghost's username
- **`download`** — Returns actual file content from the virtual filesystem
- **`whoami`** — Returns the generated username
- **`screenshot`** — Returns a valid (black) PNG image

Any unrecognized command returns `UnknownMessageType` — the same behavior as a real implant.

---

## How It Works

```
┌──────────────┐     mTLS + yamux       ┌──────────────────┐
│  SliverBane  │ ◄────────────────────► │  Sliver C2       │
│              │                        │  Server          │
│  Identity    │  1. Register           │                  │
│  Generator   │ ─────────────────────► │  "New session!"  │
│              │                        │                  │
│  VFS         │  2. Operator tasks     │  Operator runs   │
│  150+ files  │ ◄───────────────────── │  ls, ps, env...  │
│              │                        │                  │
│  Protobuf    │  3. Realistic replies  │  "Looks legit"   │
│  Handlers    │ ─────────────────────► │                  │
└──────────────┘                        └──────────────────┘
```

---

## Extending

### Adding a DoS Module

Create a new file in `internal/engine/dos/`:

```go
package dos

import (
    "sliverbane/internal/protocol"
    "github.com/hashicorp/yamux"
)

type MyAttack struct{}

func init() { Register(&MyAttack{}) }

func (a *MyAttack) Name() string        { return "my-attack" }
func (a *MyAttack) Description() string { return "Description of the attack" }
func (a *MyAttack) Execute(session *yamux.Session, key *protocol.EnvelopeKey) error {
    // Attack logic here
    return nil
}
```

---


<p align="center"><sub>Free Palestine.</sub></p>
