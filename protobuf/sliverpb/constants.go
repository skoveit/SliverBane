package sliverpb

// Message type constants ported from Sliver's constants.go
// Order is APPEND ONLY: matches the iota-based enum from the real Sliver source.
const (
	MsgRegister                 = uint32(1 + iota) // 1
	MsgTaskReq                                     // 2
	MsgPing                                        // 3
	MsgKillSessionReq                              // 4
	MsgLsReq                                       // 5
	MsgLs                                          // 6
	MsgDownloadReq                                 // 7
	MsgDownload                                    // 8
	MsgUploadReq                                   // 9
	MsgUpload                                      // 10
	MsgCdReq                                       // 11
	MsgPwdReq                                      // 12
	MsgPwd                                         // 13
	MsgRmReq                                       // 14
	MsgRm                                          // 15
	MsgMkdirReq                                    // 16
	MsgMkdir                                       // 17
	MsgPsReq                                       // 18 ← NOT 19
	MsgPs                                          // 19
	MsgShellReq                                    // 20
	MsgShell                                       // 21
	MsgTunnelData                                  // 22
	MsgTunnelClose                                 // 23
	MsgProcessDumpReq                              // 24
	MsgProcessDump                                 // 25
	MsgImpersonateReq                              // 26
	MsgImpersonate                                 // 27
	MsgRunAsReq                                    // 28
	MsgRunAs                                       // 29
	MsgRevToSelf                                   // 30
	MsgRevToSelfReq                                // 31
	MsgInvokeGetSystemReq                          // 32
	MsgGetSystem                                   // 33
	MsgInvokeExecuteAssemblyReq                    // 34
	MsgExecuteAssemblyReq                          // 35
	MsgExecuteAssembly                             // 36
	MsgInvokeMigrateReq                            // 37
	MsgSideloadReq                                 // 38
	MsgSideload                                    // 39
	MsgSpawnDllReq                                 // 40
	MsgSpawnDll                                    // 41
	MsgIfconfigReq                                 // 42
	MsgIfconfig                                    // 43
	MsgExecuteReq                                  // 44
	MsgTerminateReq                                // 45
	MsgTerminate                                   // 46
	MsgScreenshotReq                               // 47
	MsgScreenshot                                  // 48
	MsgNetstatReq                                  // 49

	// Pivots
	MsgPivotStartListenerReq  // 50
	MsgPivotStopListenerReq   // 51
	MsgPivotListenersReq      // 52
	MsgPivotListeners         // 53
	MsgPivotPeerPing          // 54
	MsgPivotServerPing        // 55
	MsgPivotServerKeyExchange // 56
	MsgPivotPeerEnvelope      // 57
	MsgPivotPeerFailure       // 58
	MsgPivotSessionEnvelope   // 59

	// Services
	MsgStartServiceReq  // 60
	MsgStartService     // 61
	MsgStopServiceReq   // 62
	MsgRemoveServiceReq // 63

	// Tokens
	MsgMakeTokenReq // 64
	MsgMakeToken    // 65

	// Env
	MsgEnvReq    // 66
	MsgEnvInfo   // 67
	MsgSetEnvReq // 68
	MsgSetEnv    // 69

	// Execute Windows
	MsgExecuteWindowsReq // 70

	// Registry
	MsgRegistryReadReq      // 71
	MsgRegistryWriteReq     // 72
	MsgRegistryCreateKeyReq // 73

	// WireGuard
	MsgWGStartPortFwdReq   // 74
	MsgWGStopPortFwdReq    // 75
	MsgWGStartSocksReq     // 76
	MsgWGStopSocksReq      // 77
	MsgWGListForwardersReq // 78
	MsgWGListSocksReq      // 79

	// Portfwd
	MsgPortfwdReq // 80
	MsgPortfwd    // 81

	// Socks
	MsgSocksData // 82

	// Reconfigure
	MsgReconfigureReq // 83
	MsgReconfigure    // 84

	// UnsetEnv
	MsgUnsetEnvReq // 85

	// SSH
	MsgSSHCommandReq // 86

	// GetPrivs
	MsgGetPrivsReq // 87

	// Registry list
	MsgRegistrySubKeysListReq // 88
	MsgRegistryListValuesReq  // 89

	// Extensions
	MsgRegisterExtensionReq // 90
	MsgCallExtensionReq     // 91
	MsgListExtensionsReq    // 92

	// Beacons
	MsgBeaconRegister // 93
	MsgBeaconTasks    // 94

	// Sessions
	MsgOpenSession  // 95
	MsgCloseSession // 96

	// Registry delete
	MsgRegistryDeleteKeyReq // 97

	// Mv
	MsgMvReq // 98
	MsgMv    // 99

	// Token owner
	MsgCurrentTokenOwnerReq           // 100
	MsgCurrentTokenOwner              // 101
	MsgInvokeInProcExecuteAssemblyReq // 102
	MsgRportFwdStopListenerReq        // 103
	MsgRportFwdStartListenerReq       // 104
	MsgRportFwdListener               // 105
	MsgRportFwdListeners              // 106
	MsgRportFwdListenersReq           // 107
	MsgRPortfwdReq                    // 108

	// Chmod/Chown/Chtimes
	MsgChmodReq   // 109
	MsgChmod      // 110
	MsgChownReq   // 111
	MsgChown      // 112
	MsgChtimesReq // 113
	MsgChtimes    // 114

	// Memfiles
	MsgMemfilesListReq // 115
	MsgMemfilesAddReq  // 116
	MsgMemfilesAdd     // 117
	MsgMemfilesRmReq   // 118
	MsgMemfilesRm      // 119

	// Wasm
	MsgRegisterWasmExtensionReq   // 120
	MsgDeregisterWasmExtensionReq // 121
	MsgRegisterWasmExtension      // 122
	MsgListWasmExtensionsReq      // 123
	MsgListWasmExtensions         // 124
	MsgExecWasmExtensionReq       // 125
	MsgExecWasmExtension          // 126

	// Cp
	MsgCpReq // 127
	MsgCp    // 128

	// Grep
	MsgGrepReq // 129

	// Services v2
	MsgServicesReq           // 130
	MsgServiceDetailReq      // 131
	MsgStartServiceByNameReq // 132

	// Registry hive
	MsgRegistryReadHiveReq // 133

	// Mount
	MsgMountReq // 134

	// Shell resize
	MsgShellResizeReq // 135

	// Execute children
	MsgExecuteChildrenReq // 136
)
