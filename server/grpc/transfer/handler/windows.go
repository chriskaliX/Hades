package handler

import (
	"encoding/json"
	"fmt"
	pb "hboat/grpc/transfer/proto"
)

type WinClientNode int

const (
	// rootkit
	NF_SSDT_ID           WinClientNode = 100
	NF_IDT_ID            WinClientNode = 101
	NF_GDT_ID            WinClientNode = 102
	NF_DPC_ID            WinClientNode = 103
	NF_SYSCALLBACK_ID    WinClientNode = 104
	NF_SYSPROCESSTREE_ID WinClientNode = 105
	NF_OBJ_ID            WinClientNode = 106
	NF_IRP_ID            WinClientNode = 107
	NF_FSD_ID            WinClientNode = 108
	NF_MOUSEKEYBOARD_ID  WinClientNode = 109
	NF_NETWORK_ID        WinClientNode = 110
	NF_PROCESS_ENUM      WinClientNode = 111
	NF_PROCESS_KILL      WinClientNode = 112
	NF_PROCESS_MOD       WinClientNode = 113
	NF_PE_DUMP           WinClientNode = 114
	NF_SYSMOD_ENUM       WinClientNode = 115

	// kernel
	NF_PROCESS_INFO     WinClientNode = 150
	NF_THREAD_INFO      WinClientNode = 151
	NF_IMAGEGMOD_INFO   WinClientNode = 152
	NF_REGISTERTAB_INFO WinClientNode = 153
	NF_FILE_INFO        WinClientNode = 154
	NF_SESSION_INFO     WinClientNode = 155

	// user
	UF_PROCESS_ENUM           WinClientNode = 200
	UF_PROCESS_PID_TREE       WinClientNode = 201
	UF_SYSAUTO_START          WinClientNode = 202
	UF_SYSNET_INFO            WinClientNode = 203
	UF_SYSSESSION_INFO        WinClientNode = 204
	UF_SYSINFO_ID             WinClientNode = 206
	UF_SYSLOG_ID              WinClientNode = 207
	UF_SYSUSER_ID             WinClientNode = 208
	UF_SYSSERVICE_SOFTWARE_ID WinClientNode = 209
	UF_SYSFILE_ID             WinClientNode = 210
	UF_FILE_INFO              WinClientNode = 211
	UF_ROOTKIT_ID             WinClientNode = 212

	// etw

	NF_EXIT WinClientNode = 1000
)

type KRootkitSsdt struct {
	Win_Rootkit_Ssdt_id         string `json:"win_rootkit_ssdt_id"`
	Win_Rootkit_Ssdt_offsetaddr string `json:"win_rootkit_ssdt_offsetaddr"`
}
type KRootkitIdt struct {
	Win_Rootkit_Idt_id         string `json:"win_rootkit_idt_id"`
	Win_Rootkit_Idt_offsetaddr string `json:"win_rootkit_idt_offsetaddr"`
}
type KRootkitDpc struct {
	Win_Rootkit_Dpc             string `json:"win_rootkit_dpc"`
	Win_Rootkit_Dpc_timeobj     string `json:"win_rootkit_dpc_timeobj"`
	Win_Rootkit_Dpc_timeroutine string `json:"win_rootkit_dpc_timeroutine"`
	Win_Rootkit_Dpc_periodtime  string `json:"win_rootkit_dpc_periodtime"`
}
type KRootkitFsd struct {
	Win_Rootkit_Fsd_fsdmod            string `json:"win_rootkit_is_fsdmod"`
	Win_Rootkit_Fsd_fsdfastfat_id     string `json:"win_rootkit_fsdfastfat_id"`
	Win_Rootkit_Fsd_fsdfastfat_mjaddr string `json:"win_rootkit_fsdfastfat_mjaddr"`
	Win_Rootkit_Fsd_fsdntfs_id        string `json:"win_rootkit_fsdntfs_id"`
	Win_Rootkit_Fsd_fsdntfs_mjaddr    string `json:"win_rootkit_fsdntfs_mjaddr"`
}
type kRootkitMouseKeyMod struct {
	Win_Rootkit_MouseKey_Mousekey_mod string `json:"win_rootkit_is_mousekeymod"`
	Win_Rootkit_MouseKey_Mouse_id     string `json:"win_rootkit_Mouse_id"`
	Win_Rootkit_MouseKey_Mouse_mjaddr string `json:"win_rootkit_Mouse_mjaddr"`
	Win_Rootkit_MouseKey_i8042_id     string `json:"win_rootkit_i8042_id"`
	Win_Rootkit_MouseKey_i8042_mjaddr string `json:"win_rootkit_i8042_mjaddr"`
	Win_Rootkit_MouseKey_kbd_id       string `json:"win_rootkit_kbd_id"`
	Win_Rootkit_MouseKey_kbd_mjaddr   string `json:"win_rootkit_kbd_mjaddr"`
}
type kRootkitNetWork struct {
	Win_Rootkit_Net_mod               string `json:"win_rootkit_is_mod"`
	Win_Rootkit_Net_tcp_pid           string `json:"win_rootkit_tcp_pid"`
	Win_Rootkit_Net_tcp_localIp_port  string `json:"win_rootkit_tcp_localIp_port"`
	Win_Rootkit_Net_tcp_remoteIp_port string `json:"win_rootkit_tcp_remoteIp_port"`
	Win_Rootkit_Net_tcp_Status        string `json:"win_rootkit_tcp_Status"`
	Win_Rootkit_Net_udp_pid           string `json:"win_rootkit_udp_pid"`
	Win_Rootkit_Net_udp_localIp_port  string `json:"win_rootkit_udp_localIp_port"`
}
type kRootkitProcessInfo struct {
	Win_Rootkit_Process_pid  string `json:"win_rootkit_process_pid"`
	Win_Rootkit_Process_Info string `json:"win_rootkit_process_info"`
}
type kRootkitProcessMod struct {
	Win_Rootkit_ProcessMod_pid         string `json:"win_rootkit_processmod_pid"`
	Win_Rootkit_ProcessMod_DllBase     string `json:"win_rootkit_process_DllBase"`
	Win_Rootkit_ProcessMod_SizeofImage string `json:"win_rootkit_process_SizeofImage"`
	Win_Rootkit_ProcessMod_EntryPoint  string `json:"win_rootkit_process_EntryPoint"`
	Win_Rootkit_ProcessMod_BaseDllName string `json:"win_rootkit_process_BaseDllName"`
	Win_Rootkit_ProcessMod_FullDllName string `json:"win_rootkit_process_FullDllName"`
}
type kRootkitSysMod struct {
	Win_Rootkit_SysMod_DllBase     string `json:"win_rootkit_sys_DllBase"`
	Win_Rootkit_SysMod_FullDllName string `json:"win_rootkit_sys_FullDllName"`
}
type KMonitorProcess struct {
	Win_SysMonitor_process_parentpid        string `json:"win_sysmonitor_process_parentpid"`
	Win_SysMonitor_process_pid              string `json:"win_sysmonitor_process_pid"`
	Win_SysMonitor_process_endprocess       string `json:"win_sysmonitor_process_endprocess"`
	Win_SysMonitor_process_queryprocesspath string `json:"win_sysmonitor_process_queryprocesspath"`
	Win_SysMonitor_process_processpath      string `json:"win_sysmonitor_process_processpath"`
	Win_SysMonitor_process_commandLine      string `json:"win_sysmonitor_process_commandLine"`
}
type KMonitorThread struct {
	Win_SysMonitor_thread_pid    string `json:"win_sysmonitor_thread_pid"`
	Win_SysMonitor_thread_id     string `json:"win_sysmonitor_thread_id"`
	Win_SysMonitor_thread_status string `json:"win_sysmonitor_thread_status"`
}
type KMonitorMod struct {
	Win_SysMonitor_mod_pid      string `json:"win_sysmonitor_mod_pid"`
	Win_SysMonitor_mod_base     string `json:"win_sysmonitor_mod_base"`
	Win_SysMonitor_mod_size     string `json:"win_sysmonitor_mod_size"`
	Win_SysMonitor_mod_path     string `json:"win_sysmonitor_mod_path"`
	Win_SysMonitor_mod_sysimage string `json:"win_sysmonitor_mod_sysimage"`
}
type KMonitorRegtab struct {
	Win_SysMonitor_regtab_pid     string `json:"win_sysmonitor_regtab_pid"`
	Win_SysMonitor_regtab_tpid    string `json:"win_sysmonitor_regtab_tpid"`
	Win_SysMonitor_regtab_opeares string `json:"win_sysmonitor_regtab_opeares"`
}
type KMonitorFileInfo struct {
	Win_SysMonitor_file_pid           string `json:"win_sysmonitor_file_pid"`
	Win_SysMonitor_file_tpid          string `json:"win_sysmonitor_file_tpid"`
	Win_SysMonitor_file_name          string `json:"win_sysmonitor_file_name"`
	Win_SysMonitor_file_dosname       string `json:"win_sysmonitor_file_dosname"`
	Win_SysMonitor_file_LockOperation string `json:"win_sysmonitor_file_LockOperation"`
	Win_SysMonitor_file_DeletePending string `json:"win_sysmonitor_file_DeletePending"`
	Win_SysMonitor_file_ReadAccess    string `json:"win_sysmonitor_file_ReadAccess"`
	Win_SysMonitor_file_WriteAccess   string `json:"win_sysmonitor_file_WriteAccess"`
	Win_SysMonitor_file_DeleteAccess  string `json:"win_sysmonitor_file_DeleteAccess"`
	Win_SysMonitor_file_SharedRead    string `json:"win_sysmonitor_file_SharedRead"`
	Win_SysMonitor_file_SharedWrite   string `json:"win_sysmonitor_file_SharedWrite"`
	Win_SysMonitor_file_SharedDelete  string `json:"win_sysmonitor_file_SharedDelete"`
	Win_SysMonitor_file_file_flag     string `json:"win_sysmonitor_file_flag"`
}
type KMonitorSession struct {
	Win_SysMonitor_session_pid       string `json:"win_sysmonitor_session_pid"`
	Win_SysMonitor_session_tpid      string `json:"win_sysmonitor_session_tpid"`
	Win_SysMonitor_session_event     string `json:"win_sysmonitor_session_event"`
	Win_SysMonitor_session_sessionid string `json:"win_sysmonitor_session_sessionid"`
}
type UProcessInfo struct {
	Win_User_Process_Pid       string `json:"win_ser_process_pid"`
	Win_User_Process_Pribase   string `json:"win_user_process_pribase"`
	Win_User_Process_Thrcout   string `json:"win_user_process_thrcout"`
	Win_User_Process_Parenid   string `json:"win_user_process_parenid"`
	Win_User_Process_Path      string `json:"win_user_process_Path"`
	Win_User_Process_szExeFile string `json:"win_user_process_szExeFile"`
}
type UAutoRun struct {
	Win_User_autorun_flag        string `json:"win_user_autorun_flag"`
	Win_User_autorun_regName     string `json:"win_user_autorun_regName"`
	Win_User_autorun_regKey      string `json:"win_user_autorun_regKey"`
	Win_User_autorun_tschname    string `json:"win_user_autorun_tschname"`
	Win_User_autorun_tscState    string `json:"win_user_autorun_tscState"`
	Win_User_autorun_tscLastTime string `json:"win_user_autorun_tscLastTime"`
	Win_User_autorun_tscNextTime string `json:"win_user_autorun_tscNextTime"`
	Win_User_autorun_tscCommand  string `json:"win_user_autorun_tscCommand"`
}
type UNet struct {
	Win_User_net_flag   string `json:"win_user_net_flag"`
	Win_User_net_src    string `json:"win_user_net_src"`
	Win_User_net_dst    string `json:"win_user_net_dst"`
	Win_User_net_status string `json:"win_user_net_status"`
	Win_User_net_pid    string `json:"win_user_net_pid"`
}
type UAccount struct {
	Win_User_sysuser_user string `json:"win_user_sysuser_user"`
	Win_User_sysuser_name string `json:"win_user_sysuser_name"`
	Win_User_sysuser_sid  string `json:"win_user_sysuser_sid"`
	Win_User_sysuser_flag string `json:"win_user_sysuser_flag"`
}
type USoftwareServer struct {
	Win_User_softwareserver_flag    string `json:"win_user_softwareserver_flag"`
	Win_User_server_lpsName         string `json:"win_user_server_lpsName"`
	Win_User_server_lpdName         string `json:"win_user_server_lpdName"`
	Win_User_server_lpPath          string `json:"win_user_server_lpPath"`
	Win_User_server_lpDescr         string `json:"win_user_server_lpDescr"`
	Win_User_server_status          string `json:"win_user_server_status"`
	Win_User_software_lpsName       string `json:"win_user_software_lpsName"`
	Win_User_software_Size          string `json:"win_user_software_Size"`
	Win_User_software_Ver           string `json:"win_user_software_Ver"`
	Win_User_software_installpath   string `json:"win_user_software_installpath"`
	Win_User_software_uninstallpath string `json:"win_user_software_uninstallpath"`
	Win_User_software_data          string `json:"win_user_software_data"`
	Win_User_software_venrel        string `json:"win_user_software_venrel"`
}
type UDriectInfo struct {
	Win_User_driectinfo_flag     string `json:"win_user_driectinfo_flag"`
	Win_User_driectinfo_filecout string `json:"win_user_driectinfo_filecout"`
	Win_User_driectinfo_size     string `json:"win_user_driectinfo_size"`
	Win_User_driectinfo_filename string `json:"win_user_driectinfo_filename"`
	Win_User_driectinfo_filePath string `json:"win_user_driectinfo_filePath"`
	Win_User_driectinfo_fileSize string `json:"win_user_driectinfo_fileSize"`
}
type UFileInfo struct {
	Win_User_fileinfo_filename             string `json:"win_user_fileinfo_filename"`
	Win_User_fileinfo_dwFileAttributes     string `json:"win_user_fileinfo_dwFileAttributes"`
	Win_User_fileinfo_dwFileAttributesHide string `json:"win_user_fileinfo_dwFileAttributesHide"`
	Win_User_fileinfo_md5                  string `json:"win_user_fileinfo_md5"`
	Win_User_fileinfo_m_seFileSizeof       string `json:"win_user_fileinfo_m_seFileSizeof"`
	Win_User_fileinfo_seFileAccess         string `json:"win_user_fileinfo_seFileAccess"`
	Win_User_fileinfo_seFileCreate         string `json:"win_user_fileinfo_seFileCreate"`
	Win_User_fileinfo_seFileModify         string `json:"win_user_fileinfo_seFileModify"`
}
type UEtwProcessinfo struct {
	Win_Etw_processinfo_pid  string `json:"win_etw_processinfo_pid"`
	Win_Etw_processinfo_Path string `json:"win_etw_processinfo_path"`
}
type UEtwThreadinfo struct {
	Win_Etw_threadinfo_pid            string `json:"win_etw_threadinfo_pid"`
	Win_Etw_threadinfo_tid            string `json:"win_etw_threadinfo_tid"`
	Win_Etw_threadinfo_Win32StartAddr string `json:"win_etw_threadinfo_win32startaddr"`
	Win_Etw_threadinfo_ThreadFlags    string `json:"win_etw_threadinfo_flags"`
}
type UEtwImageModinfo struct {
	Win_Etw_imageinfo_ProcessId      string `json:"win_etw_imageinfo_processId"`
	Win_Etw_imageinfo_ImageBase      string `json:"win_etw_imageinfo_imageBase"`
	Win_Etw_imageinfo_ImageSize      string `json:"win_etw_imageinfo_imageSize"`
	Win_Etw_imageinfo_SignatureLevel string `json:"win_etw_imageinfo_signatureLevel"`
	Win_Etw_imageinfo_SignatureType  string `json:"win_etw_imageinfo_signatureType"`
	Win_Etw_imageinfo_ImageChecksum  string `json:"win_etw_imageinfo_imageChecksum"`
	Win_Etw_imageinfo_TimeDateStamp  string `json:"win_etw_imageinfo_timeDateStamp"`
	Win_Etw_imageinfo_DefaultBase    string `json:"win_etw_imageinfo_defaultBase"`
	Win_Etw_imageinfo_FileName       string `json:"win_etw_imageinfo_fileName"`
}
type UEtwFileIoinfo struct {
}
type UEtwResgiterTabinfo struct {
	Win_Etw_regtab_InitialTime string `json:"win_etw_regtab_initialTime"`
	Win_Etw_regtab_Status      string `json:"win_etw_regtab_status"`
	Win_Etw_regtab_Index       string `json:"win_etw_regtab_index"`
	Win_Etw_regtab_KeyHandle   string `json:"win_etw_regtab_keyHandle"`
	Win_Etw_regtab_KeyName     string `json:"win_etw_regtab_keyName"`
}
type UEtwNetWorkTabinfo struct {
	Win_Etw_network_addressFamily   string `json:"win_network_addressfamily"`
	Win_Etw_network_LocalAddr       string `json:"win_network_localaddr"`
	Win_Etw_network_toLocalPort     string `json:"win_network_toLocalport"`
	Win_Etw_network_protocol        string `json:"win_network_protocol"`
	Win_Etw_network_RemoteAddr      string `json:"win_network_remoteaddr"`
	Win_Etw_network_toRemotePort    string `json:"win_network_toremoteport"`
	Win_Etw_network_processPath     string `json:"win_network_procespath"`
	Win_Etw_network_processPathSize string `json:"win_network_processpathsize"`
	Win_Etw_network_processId       string `json:"win_network_processid"`
}

// 2021-11-27 添加win客户端解析函数
// 2022-4-4数据改版
func ParseWinDataDispatch(hb map[string]string, req *pb.RawData, dataType int) {
	udata := hb["udata"]
	// golang switch从上到下遍历去匹配 - 理论上效率和if else if 一致
	switch dataType {
	case 100:
		var krootkitssdt KRootkitSsdt
		err := json.Unmarshal([]byte(udata), &krootkitssdt)
		if err != nil {
			fmt.Printf("unarshar err=%v\n", err)
			return
		}
		ssdt_id := krootkitssdt.Win_Rootkit_Ssdt_id
		ssdt_offset := krootkitssdt.Win_Rootkit_Ssdt_offsetaddr
		fmt.Printf("[ArkLog] sstd_id: %s - sstd_addr: %s\n", ssdt_id, ssdt_offset)
	case 101:
		var krootkitidt KRootkitIdt
		err := json.Unmarshal([]byte(udata), &krootkitidt)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		idt_id := krootkitidt.Win_Rootkit_Idt_id
		idt_offset := krootkitidt.Win_Rootkit_Idt_offsetaddr
		fmt.Printf("[ArkLog] idt_id: %s - idt_addr: %s\n", idt_id, idt_offset)
	case 103:
		var krootkitdpc KRootkitDpc
		err := json.Unmarshal([]byte(udata), &krootkitdpc)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		dpc := krootkitdpc.Win_Rootkit_Dpc
		//dpctimeobj :=krootkitdpc.win_rootkit_dpc_timeobj
		dpcrout := krootkitdpc.Win_Rootkit_Dpc_timeroutine
		dpctime := krootkitdpc.Win_Rootkit_Dpc_periodtime
		fmt.Printf("[ArkLog] dpcaddr: %s - dpc_time: %s - dpc_route: %s\n", dpc, dpctime, dpcrout)
	case 108:
		var krootkitfsd KRootkitFsd
		err := json.Unmarshal([]byte(udata), &krootkitfsd)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		mod := krootkitfsd.Win_Rootkit_Fsd_fsdmod
		if mod == "1" {
			id := krootkitfsd.Win_Rootkit_Fsd_fsdfastfat_id
			mjaddr := krootkitfsd.Win_Rootkit_Fsd_fsdfastfat_mjaddr
			fmt.Printf("[ArkLog] fastfatid: %s - fastfataddr: %s\n", id, mjaddr)
		} else if mod == "2" {
			id := krootkitfsd.Win_Rootkit_Fsd_fsdntfs_id
			mjaddr := krootkitfsd.Win_Rootkit_Fsd_fsdntfs_mjaddr
			fmt.Printf("[ArkLog] ntfsid: %s - ntfsaddr: %s\n", id, mjaddr)
		}
	case 109:
		var krootkitmousekey kRootkitMouseKeyMod
		err := json.Unmarshal([]byte(udata), &krootkitmousekey)
		if err != nil {
			fmt.Printf("unarshar err=%v\n", err)
			return
		}
		mod := krootkitmousekey.Win_Rootkit_MouseKey_Mousekey_mod
		switch mod {
		case "1":
			id := krootkitmousekey.Win_Rootkit_MouseKey_Mouse_id
			mjaddr := krootkitmousekey.Win_Rootkit_MouseKey_Mouse_mjaddr
			fmt.Printf("[ArkLog] fastfatid: %s - fastfataddr: %s\n", id, mjaddr)
		case "2":
			id := krootkitmousekey.Win_Rootkit_MouseKey_i8042_id
			mjaddr := krootkitmousekey.Win_Rootkit_MouseKey_i8042_mjaddr
			fmt.Printf("[ArkLog] ntfsid: %s - ntfsaddr: %s\n", id, mjaddr)
		case "3":
			id := krootkitmousekey.Win_Rootkit_MouseKey_kbd_id
			mjaddr := krootkitmousekey.Win_Rootkit_MouseKey_kbd_mjaddr
			fmt.Printf("[ArkLog] ntfsid: %s - ntfsaddr: %s\n", id, mjaddr)
		}
	case 110:
		var krootkitnet kRootkitNetWork
		err := json.Unmarshal([]byte(udata), &krootkitnet)
		if err != nil {
			fmt.Printf("unarshar err=%v\n", err)
			return
		}
		mod := krootkitnet.Win_Rootkit_Net_mod
		switch mod {
		case "1":
			pid := krootkitnet.Win_Rootkit_Net_tcp_pid
			localaddrip := krootkitnet.Win_Rootkit_Net_tcp_localIp_port
			remoteadrip := krootkitnet.Win_Rootkit_Net_tcp_remoteIp_port
			sockStatus := krootkitnet.Win_Rootkit_Net_tcp_Status
			fmt.Printf("[ArkLog] tcp_pid: %s - local:port %s - remote:port %s - status: %s\n", pid, localaddrip, remoteadrip, sockStatus)
		case "2":
			pid := krootkitnet.Win_Rootkit_Net_udp_pid
			localaddrip := krootkitnet.Win_Rootkit_Net_udp_localIp_port
			fmt.Printf("[ArkLog] udp_pid: %s - local:port %s\n", pid, localaddrip)
		}
	case 111:
		var kprocessinfo kRootkitProcessInfo
		err := json.Unmarshal([]byte(udata), &kprocessinfo)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		processpid := kprocessinfo.Win_Rootkit_Process_pid
		processinfo := kprocessinfo.Win_Rootkit_Process_Info
		fmt.Printf("pid: %s - processinfo %s\n", processpid, processinfo)
	case 113:
		var kprocessmod kRootkitProcessMod
		err := json.Unmarshal([]byte(udata), &kprocessmod)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		pid := kprocessmod.Win_Rootkit_ProcessMod_pid
		// process_modbase :=kprocessmod.Win_Rootkit_ProcessMod_DllBase
		// process_modimage := kprocessmod.Win_Rootkit_ProcessMod_SizeofImage
		// process_modentrypoint := kprocessmod.Win_Rootkit_ProcessMod_EntryPoint
		// process_moddllname := kprocessmod.Win_Rootkit_ProcessMod_BaseDllName
		process_modfullname := kprocessmod.Win_Rootkit_ProcessMod_FullDllName
		fmt.Printf("pid: %s - modpath %s\n", pid, process_modfullname)
	case 115:
		var ksysmod kRootkitSysMod
		err := json.Unmarshal([]byte(udata), &ksysmod)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		sysddlbase := ksysmod.Win_Rootkit_SysMod_DllBase
		sys_modfullname := ksysmod.Win_Rootkit_SysMod_FullDllName
		fmt.Printf("[ArkLog] sysbaseaddr: %s - syspath %s\n", sysddlbase, sys_modfullname)
	case 150:
		var kmonprocess KMonitorProcess
		err := json.Unmarshal([]byte(udata), &kmonprocess)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		sysmon_pro_parentpid := kmonprocess.Win_SysMonitor_process_parentpid
		sysmon_pro_pid := kmonprocess.Win_SysMonitor_process_pid
		sysmon_pro_endpro := kmonprocess.Win_SysMonitor_process_endprocess
		sysmon_pro_queryprocesspath := kmonprocess.Win_SysMonitor_process_queryprocesspath
		if sysmon_pro_endpro == "1" {
			// 启动进程
			//sysmon_pro_processpath := kmonprocess.Win_SysMonitor_process_processpath
			sysmon_pro_commandLine := kmonprocess.Win_SysMonitor_process_commandLine
			fmt.Printf("[SysMonitor] Peocess Start - Parentpid: %s Pid: %s querypath %s cmdline %s\n", sysmon_pro_parentpid, sysmon_pro_pid, sysmon_pro_queryprocesspath, sysmon_pro_commandLine)
			return
		}
		// 结束进程
		fmt.Printf("[SysMonitor] Peocess End - Parentpid: %s Pid: %s querypath %s\n", sysmon_pro_parentpid, sysmon_pro_pid, sysmon_pro_queryprocesspath)
	case 151:
		var kmonthread KMonitorThread
		err := json.Unmarshal([]byte(udata), &kmonthread)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		sysmon_thr_pid := kmonthread.Win_SysMonitor_thread_pid
		sysmon_thr_tpid := kmonthread.Win_SysMonitor_thread_id
		sysmon_thr_status := kmonthread.Win_SysMonitor_thread_status
		fmt.Printf("[SysMonitor] Thread:%s Tid:%s Status:%s\n", sysmon_thr_pid, sysmon_thr_tpid, sysmon_thr_status)
	case 152:
		var kmonmod KMonitorMod
		err := json.Unmarshal([]byte(udata), &kmonmod)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		sysmon_mod_pid := kmonmod.Win_SysMonitor_mod_pid
		sysmon_mod_base := kmonmod.Win_SysMonitor_mod_base
		sysmon_mod_size := kmonmod.Win_SysMonitor_mod_size
		sysmon_mod_path := kmonmod.Win_SysMonitor_mod_path
		sysmon_mod_sysimage := kmonmod.Win_SysMonitor_mod_sysimage
		fmt.Printf("[SysMonitor] Image pid: %s base: %s size: %s path: %s, image:%s\n", sysmon_mod_pid, sysmon_mod_base, sysmon_mod_size, sysmon_mod_path, sysmon_mod_sysimage)
	case 153:
		var kmonreg KMonitorRegtab
		err := json.Unmarshal([]byte(udata), &kmonreg)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		sysmon_reg_pid := kmonreg.Win_SysMonitor_regtab_pid
		sysmon_reg_tpid := kmonreg.Win_SysMonitor_regtab_tpid
		sysmon_reg_opeare := kmonreg.Win_SysMonitor_regtab_opeares
		fmt.Println("[SysMonitor] register", sysmon_reg_pid, sysmon_reg_tpid, sysmon_reg_opeare)
	case 154:
		var kmonfileobj KMonitorFileInfo
		err := json.Unmarshal([]byte(udata), &kmonfileobj)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		sysmon_file_pid := kmonfileobj.Win_SysMonitor_file_pid
		// sysmon_file_tpid := hb["win_sysmonitor_file_tpid"]
		sysmon_file_dosname := kmonfileobj.Win_SysMonitor_file_dosname
		sysmon_file_name := kmonfileobj.Win_SysMonitor_file_name
		// sysmon_file_LockOperation := hb["win_sysmonitor_file_LockOperation"]
		// sysmon_file_DeletePending := hb["win_sysmonitor_file_DeletePending"]
		// sysmon_file_ReadAccess := hb["win_sysmonitor_file_ReadAccess"]
		// sysmon_file_WriteAccess := hb["win_sysmonitor_file_WriteAccess"]
		// sysmon_file_DeleteAccess := hb["win_sysmonitor_file_DeleteAccess"]
		// sysmon_file_SharedRead := hb["win_sysmonitor_file_SharedRead"]
		// sysmon_file_SharedWrite := hb["win_sysmonitor_file_SharedWrite"]
		// sysmon_file_SharedDelete := hb["win_sysmonitor_file_SharedDelete"]
		// sysmon_file_flag := hb["win_sysmonitor_file_flag"]
		fmt.Println("[SysMonitor] file", sysmon_file_pid, sysmon_file_dosname, sysmon_file_name)
	case 155:
		var kmonsessionobj KMonitorSession
		err := json.Unmarshal([]byte(udata), &kmonsessionobj)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		sysmon_session_pid := kmonsessionobj.Win_SysMonitor_session_pid
		// sysmon_session_tpid := hb["win_sysmonitor_session_tpid"]
		sysmon_session_event := kmonsessionobj.Win_SysMonitor_session_event
		sysmon_session_id := kmonsessionobj.Win_SysMonitor_session_sessionid
		fmt.Printf("[SysMonitor] session pid:%s event:%s sessionid:%s\n", sysmon_session_pid, sysmon_session_event, sysmon_session_id)
	case 200:
		var uprocessinfo UProcessInfo
		err := json.Unmarshal([]byte(udata), &uprocessinfo)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		usermon_process_pid := uprocessinfo.Win_User_Process_Pid
		usermon_process_pribase := uprocessinfo.Win_User_Process_Pribase
		usermon_process_thrcout := uprocessinfo.Win_User_Process_Thrcout
		usermon_process_parenid := uprocessinfo.Win_User_Process_Parenid
		usermon_process_path := uprocessinfo.Win_User_Process_Path
		usermon_process_szexe := uprocessinfo.Win_User_Process_szExeFile
		fmt.Println("[UserLog]: Processinfo ", usermon_process_pid, usermon_process_pribase, usermon_process_thrcout, usermon_process_parenid, usermon_process_path, usermon_process_szexe)
	case 201:
	case 202:
		var uautorun UAutoRun
		err := json.Unmarshal([]byte(udata), &uautorun)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		switch uautorun.Win_User_autorun_flag {
		case "1":
			usermon_autorun_regname := uautorun.Win_User_autorun_regName
			usermon_autorun_regkey := uautorun.Win_User_autorun_regKey
			fmt.Println("[UserLog]: AutoRunReg ", usermon_autorun_regname, usermon_autorun_regkey)
		case "2":
			usermon_autorun_tscname := uautorun.Win_User_autorun_tschname
			usermon_autorun_tscstatus := uautorun.Win_User_autorun_tscState
			usermon_autorun_tsclasttime := uautorun.Win_User_autorun_tscLastTime
			usermon_autorun_tscnexttime := uautorun.Win_User_autorun_tscNextTime
			usermon_autorun_tsccommand := uautorun.Win_User_autorun_tscCommand
			fmt.Println("[UserLog]: AutoRunRegTsch ", usermon_autorun_tscname, usermon_autorun_tscstatus, usermon_autorun_tsclasttime, usermon_autorun_tscnexttime, usermon_autorun_tsccommand)
		}
	case 203:
		var unet UNet
		err := json.Unmarshal([]byte(udata), &unet)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		switch unet.Win_User_net_flag {
		case "1":
			usermon_net_src := unet.Win_User_net_src
			usermon_net_dst := unet.Win_User_net_dst
			usermon_net_status := unet.Win_User_net_status
			usermon_net_pid := unet.Win_User_net_pid
			fmt.Printf("[UserLog]: NetworkTcp %s, %s, %s, %s\n", usermon_net_src, usermon_net_dst, usermon_net_status, usermon_net_pid)
		case "2":
			usermon_net_src := unet.Win_User_net_src
			usermon_net_pid := unet.Win_User_net_pid
			fmt.Println("[UserLog]: NetworkUdp ", usermon_net_src, usermon_net_pid)
		}
	case 207:
		var uaccount UAccount
		err := json.Unmarshal([]byte(udata), &uaccount)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		usermon_user_user := uaccount.Win_User_sysuser_user
		usermon_user_name := uaccount.Win_User_sysuser_name
		usermon_user_sid := uaccount.Win_User_sysuser_sid
		usermon_user_flag := uaccount.Win_User_sysuser_flag
		fmt.Println("[UserLog]: Account ", usermon_user_user, usermon_user_name, usermon_user_sid, usermon_user_flag)
	case 208:
		var usoftwareserver USoftwareServer
		err := json.Unmarshal([]byte(udata), &usoftwareserver)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		switch usoftwareserver.Win_User_softwareserver_flag {
		case "1":
			usermon_software_Name := usoftwareserver.Win_User_server_lpsName
			usermon_software_DName := usoftwareserver.Win_User_server_lpdName
			usermon_software_Path := usoftwareserver.Win_User_server_lpPath
			usermon_software_Descr := usoftwareserver.Win_User_server_lpDescr
			usermon_software_status := usoftwareserver.Win_User_server_status
			fmt.Println("[UserLog]: Software ", usermon_software_Name, usermon_software_DName, usermon_software_Path, usermon_software_Descr, usermon_software_status)
		case "2":
			// usermon_server_Name := hb["win_user_software_lpsName"]
			// usermon_server_Size := hb["win_user_software_Size"]
			// usermon_server_Ver := hb["win_user_software_Ver"]
			// usermon_server_inPath := hb["win_user_software_installpath"]
			// usermon_server_unPath := hb["win_user_software_uninstallpath"]
			// usermon_server_data := hb["win_user_software_data"]
			// usermon_server_venrel := hb["win_user_software_venrel"]
		}
	case 209:
		var udriectinfo UDriectInfo
		err := json.Unmarshal([]byte(udata), &udriectinfo)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		switch udriectinfo.Win_User_driectinfo_flag {
		case "1":
			// usermon_driectinfo_filecout := hb["win_user_driectinfo_filecout"]
			// usermon_driectinfo_size := hb["win_user_driectinfo_size"]
		case "2":
			// hb["win_user_driectinfo_filename"]
			// hb["win_user_driectinfo_filePath"]
			// hb["win_user_driectinfo_fileSize"]
		}
	case 210:
		var ufileinfo UFileInfo
		err := json.Unmarshal([]byte(udata), &ufileinfo)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		// hb["win_user_fileinfo_filename"]
		// hb["win_user_fileinfo_dwFileAttributes"]
		// hb["win_user_fileinfo_dwFileAttributesHide"]
		// hb["win_user_fileinfo_md5"]
		// hb["win_user_fileinfo_m_seFileSizeof"]
		// hb["win_user_fileinfo_seFileAccess"]
		// hb["win_user_fileinfo_seFileCreate"]
		// hb["win_user_fileinfo_seFileModify"]
	case 300:
		var uetwprocessinfo UEtwProcessinfo
		err := json.Unmarshal([]byte(udata), &uetwprocessinfo)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		usermon_etw_process_pid := uetwprocessinfo.Win_Etw_processinfo_pid
		usermon_etw_process_path := uetwprocessinfo.Win_Etw_processinfo_Path
		fmt.Println("[EtwMonitor]: ProcessInfo: ", usermon_etw_process_pid, usermon_etw_process_path)
	case 301:
		var uetwthreadinfo UEtwThreadinfo
		err := json.Unmarshal([]byte(udata), &uetwthreadinfo)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		usermon_etw_thread_pid := uetwthreadinfo.Win_Etw_threadinfo_pid
		usermon_etw_thread_tid := uetwthreadinfo.Win_Etw_threadinfo_tid
		fmt.Println("[EtwMonitor]: ThreadInfo: ", usermon_etw_thread_pid, usermon_etw_thread_tid)
	case 302:
		var uetwimageinfo UEtwImageModinfo
		err := json.Unmarshal([]byte(udata), &uetwimageinfo)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		usermon_etw_image_pid := uetwimageinfo.Win_Etw_imageinfo_ProcessId
		usermon_etw_image_Baseaddr := uetwimageinfo.Win_Etw_imageinfo_ImageBase
		usermon_etw_image_FileName := uetwimageinfo.Win_Etw_imageinfo_FileName
		fmt.Println("[EtwMonitor]: ImageInfo: ", usermon_etw_image_pid, usermon_etw_image_Baseaddr, usermon_etw_image_FileName)
	case 303:
		var uetwnetworkinfo UEtwNetWorkTabinfo
		err := json.Unmarshal([]byte(udata), &uetwnetworkinfo)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		usermon_etw_network_pid := uetwnetworkinfo.Win_Etw_network_processId
		usermon_etw_network_protocol := uetwnetworkinfo.Win_Etw_network_protocol
		usermon_etw_network_localaddrport := uetwnetworkinfo.Win_Etw_network_LocalAddr + ":" + uetwnetworkinfo.Win_Etw_network_toLocalPort
		usermon_etw_network_Remoteport := uetwnetworkinfo.Win_Etw_network_RemoteAddr + ":" + uetwnetworkinfo.Win_Etw_network_toRemotePort
		fmt.Println("[EtwMonitor]: NetworkInfo: ", usermon_etw_network_pid, usermon_etw_network_protocol, usermon_etw_network_localaddrport, usermon_etw_network_Remoteport)
	case 304:
		var uetwregistertab UEtwResgiterTabinfo
		err := json.Unmarshal([]byte(udata), &uetwregistertab)
		if err != nil {
			fmt.Printf("unarshar err=%v", err)
			return
		}
		usermon_etw_regtab_KeyHandle := uetwregistertab.Win_Etw_regtab_KeyHandle
		usermon_etw_regtab_KeyName := uetwregistertab.Win_Etw_regtab_KeyName
		fmt.Println("[EtwMonitor]: RegisterTab: ", usermon_etw_regtab_KeyHandle, usermon_etw_regtab_KeyName)
	case 401, 402, 403, 404:
		// Etw mon enable
		// Etw mon disable
		// Kernel mon enable
		// Kernel mon disable
	}
}
