use crate::transport::RecordWriter;

pub struct Etw;

#[cfg(windows)]
mod platform {
    use std::{
        collections::HashMap,
        net::Ipv4Addr,
        ptr, slice,
        sync::{Mutex, OnceLock},
        thread,
    };

    use serde_json::{json, Value};
    use windows_sys::{
        core::GUID,
        Win32::{
            Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, ERROR_CANCELLED, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS},
            System::{
                Diagnostics::Etw::*,
                Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION},
            },
        },
    };

    use crate::{
        protocol::{Payload, Record},
        transport::{unix_timestamp, RecordWriter},
    };

    const PROVIDER_NETWORK_V4: GUID = GUID::from_u128(0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2);
    const PROVIDER_NETWORK_V6: GUID = GUID::from_u128(0xbf3a50c5_a9c9_4988_a005_2df0b7c80f80);
    const PROVIDER_PROCESS: GUID = GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);
    const PROVIDER_THREAD: GUID = GUID::from_u128(0x3d6fa8d1_fe05_11d0_9dda_00c04fd7ba7c);
    const PROVIDER_FILE: GUID = GUID::from_u128(0x90cbdc39_4a3e_11d1_84f4_0000f80464e3);
    const PROVIDER_REGISTRY: GUID = GUID::from_u128(0xae53722e_c863_11d2_8659_00c04fa321a1);
    const PROVIDER_IMAGE: GUID = GUID::from_u128(0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518);

    static WRITER: OnceLock<RecordWriter> = OnceLock::new();
    static STATE: OnceLock<Mutex<Option<EtwSession>>> = OnceLock::new();

    struct EtwSession {
        control_handle: CONTROLTRACE_HANDLE,
        trace_handle: PROCESSTRACE_HANDLE,
    }

    pub fn start(writer: RecordWriter) -> Result<usize, String> {
        let _ = WRITER.set(writer);
        let state = STATE.get_or_init(|| Mutex::new(None));
        let mut guard = state
            .lock()
            .map_err(|_| "ETW session state lock poisoned".to_string())?;
        if guard.is_some() {
            return Ok(0);
        }

        let name = kernel_logger_name();
        let mut props_buf = build_properties(&name);
        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        let mut control_handle = CONTROLTRACE_HANDLE { Value: 0 };

        let mut status = unsafe { StartTraceW(&mut control_handle, name.as_ptr(), props) };
        if status == ERROR_ALREADY_EXISTS {
            let _ = unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE { Value: 0 },
                    name.as_ptr(),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            status = unsafe { StartTraceW(&mut control_handle, name.as_ptr(), props) };
        }
        if status != ERROR_SUCCESS {
            return Err(format!("StartTraceW failed: {}", status));
        }

        let mut trace = EVENT_TRACE_LOGFILEW::default();
        trace.LoggerName = KERNEL_LOGGER_NAMEW as *mut u16;
        trace.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        trace.Anonymous2.EventRecordCallback = Some(event_callback);
        trace.BufferCallback = Some(buffer_callback);
        trace.IsKernelTrace = 1;

        let trace_handle = unsafe { OpenTraceW(&mut trace) };
        if trace_handle.Value == u64::MAX {
            let _ = unsafe {
                ControlTraceW(
                    control_handle,
                    name.as_ptr(),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            return Err("OpenTraceW failed".to_string());
        }

        let worker_handle = trace_handle;
        thread::spawn(move || {
            let status =
                unsafe { ProcessTrace(&worker_handle, 1, ptr::null_mut(), ptr::null_mut()) };
            if status != ERROR_SUCCESS && status != ERROR_CANCELLED {
                log::warn!("ProcessTrace failed: {}", status);
            }
        });

        *guard = Some(EtwSession {
            control_handle,
            trace_handle,
        });
        Ok(1)
    }

    pub fn stop() {
        let Some(state) = STATE.get() else {
            return;
        };
        let Ok(mut guard) = state.lock() else {
            return;
        };
        let Some(session) = guard.take() else {
            return;
        };

        let name = kernel_logger_name();
        let mut props_buf = build_properties(&name);
        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        unsafe {
            let _ = CloseTrace(session.trace_handle);
            let _ = ControlTraceW(
                session.control_handle,
                name.as_ptr(),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    }

    unsafe extern "system" fn buffer_callback(_logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
        1
    }

    unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
        if record.is_null() {
            return;
        }
        let record = &*record;
        let provider = record.EventHeader.ProviderId;
        if !is_supported_provider(&provider) {
            return;
        }

        let Some(buffer) = load_event_info(record) else {
            return;
        };
        let info = &*(buffer.as_ptr() as *const TRACE_EVENT_INFO);
        let props = parse_properties(record, info);
        let event_name = info_offset_string(info, info.OpcodeNameOffset);
        let task_name = info_offset_string(info, info.TaskNameOffset);

        if guid_eq(&provider, &PROVIDER_PROCESS) {
            emit_process_event(record, &props, &event_name);
        } else if guid_eq(&provider, &PROVIDER_THREAD) {
            emit_thread_event(&props, &event_name);
        } else if guid_eq(&provider, &PROVIDER_IMAGE) {
            emit_image_event(&props, &event_name);
        } else if guid_eq(&provider, &PROVIDER_FILE) {
            emit_file_event(&props, &event_name);
        } else if guid_eq(&provider, &PROVIDER_REGISTRY) {
            emit_registry_event(&props, &event_name);
        } else if guid_eq(&provider, &PROVIDER_NETWORK_V4) || guid_eq(&provider, &PROVIDER_NETWORK_V6) {
            emit_network_event(&props, &task_name, &event_name);
        }
    }

    unsafe fn load_event_info(record: &EVENT_RECORD) -> Option<Vec<u8>> {
        let mut size = 0u32;
        let status = TdhGetEventInformation(record, 0, ptr::null(), ptr::null_mut(), &mut size);
        if size == 0 || (status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS) {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        let info = buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO;
        if TdhGetEventInformation(record, 0, ptr::null(), info, &mut size) != ERROR_SUCCESS {
            return None;
        }
        Some(buffer)
    }

    unsafe fn parse_properties(
        record: &EVENT_RECORD,
        info: &TRACE_EVENT_INFO,
    ) -> HashMap<String, String> {
        let mut result = HashMap::new();
        let pointer_size = if (record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER as u16) != 0 {
            4
        } else {
            8
        };
        let mut user_len = record.UserDataLength;
        let mut data = record.UserData as *const u8;
        let properties = slice::from_raw_parts(
            info.EventPropertyInfoArray.as_ptr(),
            info.TopLevelPropertyCount as usize,
        );

        for property in properties {
            let prop_name = info_offset_string(info, property.NameOffset);
            let mut len = property.Anonymous3.length as u32;

            if (property.Flags & (PropertyStruct | PropertyParamCount)) == 0 {
                let non_struct = property.Anonymous1.nonStructType;
                let mut map_buffer = Vec::new();
                let mut map_info: *mut EVENT_MAP_INFO = ptr::null_mut();

                if non_struct.MapNameOffset != 0 {
                    let map_name = (info as *const TRACE_EVENT_INFO as *const u8)
                        .add(non_struct.MapNameOffset as usize) as *const u16;
                    let mut map_size = 0u32;
                    if TdhGetEventMapInformation(record, map_name, ptr::null_mut(), &mut map_size)
                        == ERROR_INSUFFICIENT_BUFFER
                    {
                        map_buffer.resize(map_size as usize, 0u8);
                        map_info = map_buffer.as_mut_ptr() as *mut EVENT_MAP_INFO;
                        if TdhGetEventMapInformation(record, map_name, map_info, &mut map_size)
                            != ERROR_SUCCESS
                        {
                            map_info = ptr::null_mut();
                        }
                    }
                }

                if non_struct.InType as i32 == TDH_INTYPE_BINARY
                    && non_struct.OutType as i32 == TDH_OUTTYPE_IPV6
                {
                    len = 16;
                }

                let mut value = [0u16; 512];
                let mut size = (value.len() * std::mem::size_of::<u16>()) as u32;
                let mut consumed = 0u16;
                let mut status = TdhFormatProperty(
                    info,
                    map_info,
                    pointer_size,
                    non_struct.InType,
                    non_struct.OutType,
                    len as u16,
                    user_len,
                    data,
                    &mut size,
                    value.as_mut_ptr(),
                    &mut consumed,
                );
                if status != ERROR_SUCCESS && !map_info.is_null() {
                    status = TdhFormatProperty(
                        info,
                        ptr::null_mut(),
                        pointer_size,
                        non_struct.InType,
                        non_struct.OutType,
                        len as u16,
                        user_len,
                        data,
                        &mut size,
                        value.as_mut_ptr(),
                        &mut consumed,
                    );
                }
                if status == ERROR_SUCCESS {
                    len = consumed as u32;
                    result.insert(prop_name, utf16_array_to_string(&value));
                }
            }

            if len > user_len as u32 {
                break;
            }
            user_len -= len as u16;
            data = data.add(len as usize);
        }

        result
    }

    fn emit_process_event(record: &EVENT_RECORD, props: &HashMap<String, String>, event_name: &str) {
        let pid = parse_u64(props.get("ProcessId")) as u32;
        if pid == 0 {
            return;
        }
        let parent = parse_u64(props.get("ParentId")) as u32;
        let path = props
            .get("CommandLine")
            .cloned()
            .or_else(|| props.get("ImageFileName").cloned())
            .unwrap_or_default();
        let status = if event_name.eq_ignore_ascii_case("End") {
            "0".to_string()
        } else {
            "1".to_string()
        };
        emit_json(
            300,
            json!({
                "win_etw_processinfo_eventname": event_name,
                "win_etw_processinfo_parentid": parent.to_string(),
                "win_etw_processinfo_status": status,
                "win_etw_processinfo_pid": pid.to_string(),
                "win_etw_processinfo_path": path,
            }),
        );
        let _ = record;
    }

    fn emit_thread_event(props: &HashMap<String, String>, event_name: &str) {
        let pid = parse_u64(props.get("ProcessId"));
        let tid = parse_u64(props.get("TThreadId"));
        if pid == 0 || tid == 0 {
            return;
        }
        emit_json(
            301,
            json!({
                "win_etw_threadinfo_pid": pid.to_string(),
                "win_etw_threadinfo_tid": tid.to_string(),
                "win_etw_threadinfo_win32startaddr": parse_u64(props.get("Win32StartAddr")).to_string(),
                "win_etw_threadinfo_flags": parse_u64(props.get("ThreadFlags")).to_string(),
                "win_etw_threadinfo_eventname": event_name,
            }),
        );
    }

    fn emit_image_event(props: &HashMap<String, String>, event_name: &str) {
        if event_name == "DCStart" {
            return;
        }
        let pid = parse_u64(props.get("ProcessId"));
        if pid <= 4 {
            return;
        }
        emit_json(
            302,
            json!({
                "win_etw_imageinfo_processId": pid.to_string(),
                "win_etw_imageinfo_imageBase": parse_u64(props.get("ImageBase")).to_string(),
                "win_etw_imageinfo_imageSize": parse_u64(props.get("ImageSize")).to_string(),
                "win_etw_imageinfo_signatureLevel": parse_u64(props.get("SignatureLevel")).to_string(),
                "win_etw_imageinfo_signatureType": parse_u64(props.get("SignatureType")).to_string(),
                "win_etw_imageinfo_imageChecksum": parse_u64(props.get("ImageChecksum")).to_string(),
                "win_etw_imageinfo_timeDateStamp": parse_u64(props.get("TimeDateStamp")).to_string(),
                "win_etw_imageinfo_defaultBase": parse_u64(props.get("DefaultBase")).to_string(),
                "win_etw_imageinfo_fileName": props.get("FileName").cloned().unwrap_or_default(),
                "win_etw_imageinfo_eventname": event_name,
            }),
        );
    }

    fn emit_network_event(props: &HashMap<String, String>, task_name: &str, event_name: &str) {
        let protocol = if task_name.contains("TcpIp") {
            6
        } else if task_name.contains("UdpIp") {
            17
        } else {
            return;
        };
        let local = props.get("saddr").cloned().unwrap_or_default();
        let remote = props.get("daddr").cloned().unwrap_or_default();
        if local.is_empty() && remote.is_empty() {
            return;
        }
        let family = if local.contains(':') || remote.contains(':') { 23 } else { 2 };
        let process_id = parse_u64(props.get("PID")) as u32;
        let process_path = process_path_by_pid(process_id);
        let process_path_size = process_path.encode_utf16().count();
        emit_json(
            303,
            json!({
                "win_network_addressfamily": family.to_string(),
                "win_network_localaddr": network_address_value(&local, family),
                "win_network_toLocalport": parse_u64(props.get("sport")).to_string(),
                "win_network_protocol": protocol.to_string(),
                "win_network_remoteaddr": network_address_value(&remote, family),
                "win_network_toremoteport": parse_u64(props.get("dport")).to_string(),
                "win_network_procespath": process_path,
                "win_network_processpathsize": process_path_size.to_string(),
                "win_network_processid": process_id.to_string(),
                "win_network_eventname": event_name,
            }),
        );
    }

    fn emit_registry_event(props: &HashMap<String, String>, event_name: &str) {
        if props.is_empty() {
            return;
        }
        emit_json(
            304,
            json!({
                "win_etw_regtab_initialTime": parse_i64(props.get("InitialTime")).to_string(),
                "win_etw_regtab_status": parse_u64(props.get("Status")).to_string(),
                "win_etw_regtab_index": parse_u64(props.get("Index")).to_string(),
                "win_etw_regtab_keyHandle": parse_u64(props.get("KeyHandle")).to_string(),
                "win_etw_regtab_keyName": props.get("KeyName").cloned().unwrap_or_default(),
                "win_etw_regtab_eventname": event_name,
            }),
        );
    }

    fn emit_file_event(props: &HashMap<String, String>, event_name: &str) {
        if matches!(event_name, "OperationEnd" | "QueryInfo" | "FSControl") {
            return;
        }
        if props.get("OpenPath").is_none()
            && props.get("FileName").is_none()
            && props.get("FileObject").is_none()
        {
            return;
        }
        emit_json(
            305,
            json!({
                "win_etw_fileio_eventname": event_name,
                "win_etw_fileio_FilePath": props.get("OpenPath").cloned().unwrap_or_default(),
                "win_etw_fileio_FileName": props.get("FileName").cloned().unwrap_or_default(),
                "win_etw_fileio_Tid": parse_u64(props.get("TTID")).to_string(),
                "win_etw_fileio_FileAttributes": parse_u64(props.get("FileAttributes")).to_string(),
                "win_etw_fileio_CreateOptions": parse_u64(props.get("CreateOptions")).to_string(),
                "win_etw_fileio_ShareAccess": parse_u64(props.get("ShareAccess")).to_string(),
                "win_etw_fileio_Offset": parse_u64(props.get("Offset")).to_string(),
                "win_etw_fileio_FileKey": parse_u64(props.get("FileKey")).to_string(),
                "win_etw_fileio_FileObject": parse_u64(props.get("FileObject")).to_string(),
            }),
        );
    }

    fn emit_json(data_type: i32, value: Value) {
        let Some(writer) = WRITER.get() else {
            return;
        };
        let Ok(udata) = serde_json::to_string(&value) else {
            return;
        };
        let rec = Record {
            data_type,
            timestamp: unix_timestamp(),
            data: Some(Payload {
                fields: HashMap::from([
                    ("data_type".to_string(), data_type.to_string()),
                    ("udata".to_string(), udata),
                ]),
            }),
        };
        let _ = writer.send_record(&rec);
    }

    fn info_offset_string(info: &TRACE_EVENT_INFO, offset: u32) -> String {
        if offset == 0 {
            return String::new();
        }
        unsafe {
            let ptr = (info as *const TRACE_EVENT_INFO as *const u8).add(offset as usize) as *const u16;
            read_wide(ptr)
        }
    }

    unsafe fn read_wide(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(slice::from_raw_parts(ptr, len))
    }

    fn utf16_array_to_string(buf: &[u16]) -> String {
        let end = buf.iter().position(|&ch| ch == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end]).trim().to_string()
    }

    fn network_address_value(address: &str, family: u32) -> String {
        if family == 2 {
            if let Ok(ipv4) = address.parse::<Ipv4Addr>() {
                return u32::from_le_bytes(ipv4.octets()).to_string();
            }
        }
        address.to_string()
    }

    fn process_path_by_pid(pid: u32) -> String {
        if pid == 0 {
            return String::new();
        }

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return String::new();
            }

            let mut buffer = vec![0u16; 260];
            let mut size = buffer.len() as u32;
            let status = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
            let _ = CloseHandle(handle);
            if status == 0 || size == 0 {
                return String::new();
            }

            String::from_utf16_lossy(&buffer[..size as usize])
        }
    }

    fn parse_u64(value: Option<&String>) -> u64 {
        let Some(value) = value else {
            return 0;
        };
        let value = value.trim();
        if value.is_empty() {
            return 0;
        }
        if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
            return u64::from_str_radix(hex, 16).unwrap_or(0);
        }
        value
            .parse::<u64>()
            .or_else(|_| u64::from_str_radix(value, 16))
            .unwrap_or(0)
    }

    fn parse_i64(value: Option<&String>) -> i64 {
        let Some(value) = value else {
            return 0;
        };
        let value = value.trim();
        if value.is_empty() {
            return 0;
        }
        value
            .parse::<i64>()
            .or_else(|_| i64::from_str_radix(value.trim_start_matches("0x"), 16))
            .unwrap_or(0)
    }

    fn guid_eq(left: &GUID, right: &GUID) -> bool {
        left.data1 == right.data1
            && left.data2 == right.data2
            && left.data3 == right.data3
            && left.data4 == right.data4
    }

    fn is_supported_provider(provider: &GUID) -> bool {
        guid_eq(provider, &PROVIDER_PROCESS)
            || guid_eq(provider, &PROVIDER_THREAD)
            || guid_eq(provider, &PROVIDER_IMAGE)
            || guid_eq(provider, &PROVIDER_FILE)
            || guid_eq(provider, &PROVIDER_REGISTRY)
            || guid_eq(provider, &PROVIDER_NETWORK_V4)
            || guid_eq(provider, &PROVIDER_NETWORK_V6)
    }

    fn build_properties(session_name: &[u16]) -> Vec<u8> {
        let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let buffer_size = props_size + session_name.len() * std::mem::size_of::<u16>();
        let mut buffer = vec![0u8; buffer_size];
        let props = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        unsafe {
            (*props).Wnode.BufferSize = buffer_size as u32;
            (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props).Wnode.ClientContext = 1;
            (*props).Wnode.Guid = SystemTraceControlGuid;
            (*props).BufferSize = 64;
            (*props).MinimumBuffers = 5;
            (*props).MaximumBuffers = 64;
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
            (*props).FlushTimer = 1;
            (*props).EnableFlags = EVENT_TRACE_FLAG_PROCESS
                | EVENT_TRACE_FLAG_THREAD
                | EVENT_TRACE_FLAG_IMAGE_LOAD
                | EVENT_TRACE_FLAG_NETWORK_TCPIP
                | EVENT_TRACE_FLAG_REGISTRY
                | EVENT_TRACE_FLAG_FILE_IO
                | EVENT_TRACE_FLAG_FILE_IO_INIT;
            (*props).LoggerNameOffset = props_size as u32;
            ptr::copy_nonoverlapping(
                session_name.as_ptr(),
                buffer.as_mut_ptr().add(props_size) as *mut u16,
                session_name.len(),
            );
        }
        buffer
    }

    fn kernel_logger_name() -> Vec<u16> {
        "NT Kernel Logger"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }
}

#[cfg(not(windows))]
mod platform {
    use crate::transport::RecordWriter;

    pub fn start(_writer: RecordWriter) -> Result<usize, String> {
        Err("ETW active reporting is only supported on Windows".to_string())
    }

    pub fn stop() {}
}

impl Etw {
    pub fn start(writer: RecordWriter) -> Result<usize, String> {
        platform::start(writer)
    }

    pub fn stop() {
        platform::stop()
    }
}
