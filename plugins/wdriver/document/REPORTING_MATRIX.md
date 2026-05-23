# wdriver Reporting Matrix

## Scope

This document describes the current user-mode collection and ETW reporting
surface of `plugins/wdriver`.

本文档用于说明 `plugins/wdriver` 当前已经落地的用户态采集与 ETW
上报能力，重点关注：

- server 下发任务后是否能真实采集并上报
- `Record + fields["data_type"] + fields["udata"]` 协议是否保持稳定
- 哪些模块已经完成，哪些仍是未接入或未完成状态

## Transport

- Input task frame: `uint32 little-endian length + protobuf Task`
- Output record frame: `uint32 little-endian length + protobuf Record`
- Windows payload contract:
  - `fields["data_type"]`
  - `fields["udata"]`
- Task acknowledgement:
  - `data_type = 5100`
  - fields: `token`, `status`, `msg`

## Implemented Task Matrix

| data_type | status | purpose | notes |
| --- | --- | --- | --- |
| `200` | implemented | process snapshot | active |
| `202` | implemented | autorun registry + scheduled task snapshot | `flag=1` registry, `flag=2` task scheduler |
| `203` | implemented | network socket snapshot | active |
| `207` | implemented | local account snapshot | active |
| `208` | implemented | service + installed software snapshot | `flag=1` service, `flag=2` software |
| `209` | implemented | directory enumeration | bounded by max file count |
| `210` | implemented | file detail query | includes md5 |
| `300` | implemented | ETW process event active reporting | kernel logger + TDH parser |
| `301` | implemented | ETW thread event | kernel logger + TDH parser |
| `302` | implemented | ETW image load event | kernel logger + TDH parser |
| `303` | implemented | ETW network event | kernel logger + TDH parser |
| `304` | implemented | ETW registry event | kernel logger + TDH parser |
| `305` | implemented | ETW file I/O event | kernel logger + TDH parser |

## Current Field Contract

### 200 process snapshot

- `win_user_process_pid`
- `win_user_process_pribase`
- `win_user_process_thrcout`
- `win_user_process_parenid`
- `win_user_process_Path`
- `win_user_process_szExeFile`

### 202 autorun snapshot

- `win_user_autorun_flag`
- `win_user_autorun_regName`
- `win_user_autorun_regKey`

Scheduled task record:

- `win_user_autorun_flag = 2`
- `win_user_autorun_tschname`
- `win_user_autorun_tscState`
- `win_user_autorun_tscLastTime`
- `win_user_autorun_tscNextTime`
- `win_user_autorun_tscCommand`

### 203 network snapshot

- `win_user_net_flag`
- `win_user_net_src`
- `win_user_net_dst`
- `win_user_net_status`
- `win_user_net_pid`

### 207 account snapshot

- `win_user_sysuser_user`
- `win_user_sysuser_name`
- `win_user_sysuser_sid`
- `win_user_sysuser_flag`

### 208 service/software snapshot

Service record:

- `win_user_softwareserver_flag = 1`
- `win_user_server_lpsName`
- `win_user_server_lpdName`
- `win_user_server_lpPath`
- `win_user_server_lpDescr`
- `win_user_server_status`

Software record:

- `win_user_softwareserver_flag = 2`
- `win_user_software_lpsName`
- `win_user_software_Size`
- `win_user_software_Ver`
- `win_user_software_installpath`
- `win_user_software_uninstallpath`
- `win_user_software_data`
- `win_user_software_venrel`

### 209 directory snapshot

Summary record:

- `win_user_driectinfo_flag = 1`
- `win_user_driectinfo_filecout`
- `win_user_driectinfo_size`

File record:

- `win_user_driectinfo_flag = 2`
- `win_user_driectinfo_filename`
- `win_user_driectinfo_filePath`
- `win_user_driectinfo_fileSize`

### 210 file detail snapshot

- `win_user_fileinfo_filename`
- `win_user_fileinfo_dwFileAttributes`
- `win_user_fileinfo_dwFileAttributesHide`
- `win_user_fileinfo_md5`
- `win_user_fileinfo_m_seFileSizeof`
- `win_user_fileinfo_seFileAccess`
- `win_user_fileinfo_seFileCreate`
- `win_user_fileinfo_seFileModify`

### 300 ETW process event

- `win_etw_processinfo_eventname`
- `win_etw_processinfo_parentid`
- `win_etw_processinfo_status`
- `win_etw_processinfo_pid`
- `win_etw_processinfo_path`

## Appcore Status

| module | status | notes |
| --- | --- | --- |
| `app_process` | implemented | snapshot collection |
| `app_net` | implemented | snapshot collection |
| `app_account` | implemented | snapshot collection |
| `app_autostart` | implemented | registry + task scheduler snapshot |
| `app_service_software` | partially implemented | service + software implemented |
| `app_file` | implemented | directory + file detail |
| `app_sysinfo` | not wired | no reporting task and methods remain skeletal |
| `appcore/etw` | implemented | `300-305` are connected through one ETW session |

## Test Coverage

Current test design:

- `tests/ts_appcore.rs`
  - verifies user-mode collectors return non-empty results
  - verifies directory and file detail collection
- `tests/ts_protocol.rs`
  - verifies downlink task -> stdout protobuf report -> `5100` ack
  - verifies `200/203/207/208/209/210`
  - verifies `300-305` ETW reporting smoke paths
  - verifies repeated ETW start is idempotent

## Stability And Performance Notes

- Protocol writer is protected by a mutex so ETW async reporting does not corrupt
  stdout framing while task responses are in flight.
- Directory collection is capped to avoid unbounded recursion and memory growth.
- File md5 is streamed instead of loading the whole file into memory.
- ETW currently starts one kernel logger session and shares it across `300-305`
  so repeated task activation does not create multiple competing traces.

## Known Gaps

- `app_sysinfo` is not yet part of the reporting task surface.
- some process fields still use lightweight sources and are not fully aligned
  with the C++ implementation depth.
- IPv4 ETW network addresses follow the legacy Hades-Windows numeric-string
  semantics, while IPv6 addresses remain readable string literals.
