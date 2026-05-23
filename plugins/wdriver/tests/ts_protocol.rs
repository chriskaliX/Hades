mod common;

#[cfg(windows)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        process::Command,
        thread,
        time::Duration,
    };

    use serde_json::Value;
    use wdriver::protocol::Task;

    use crate::common::{ack_status, PluginHarness};

    #[test]
    fn protocol_snapshot_tasks_emit_records_and_ack() {
        let mut plugin = PluginHarness::new();

        assert_snapshot_task(
            &mut plugin,
            Task {
                data_type: 200,
                object_name: String::new(),
                data: String::new(),
                token: "proc".to_string(),
            },
            "proc",
            &[
                "win_user_process_pid",
                "win_user_process_pribase",
                "win_user_process_thrcout",
                "win_user_process_parenid",
                "win_user_process_Path",
                "win_user_process_szExeFile",
            ],
        );

        assert_snapshot_task(
            &mut plugin,
            Task {
                data_type: 203,
                object_name: String::new(),
                data: String::new(),
                token: "net".to_string(),
            },
            "net",
            &[
                "win_user_net_flag",
                "win_user_net_src",
                "win_user_net_dst",
                "win_user_net_status",
                "win_user_net_pid",
            ],
        );

        let autorun_records = assert_snapshot_task(
            &mut plugin,
            Task {
                data_type: 202,
                object_name: String::new(),
                data: String::new(),
                token: "autorun".to_string(),
            },
            "autorun",
            &["win_user_autorun_flag"],
        );
        assert!(autorun_records.iter().any(|payload| {
            payload["win_user_autorun_flag"].as_str() == Some("2")
                && payload.get("win_user_autorun_tschname").is_some()
                && payload.get("win_user_autorun_tscState").is_some()
                && payload.get("win_user_autorun_tscLastTime").is_some()
                && payload.get("win_user_autorun_tscNextTime").is_some()
                && payload.get("win_user_autorun_tscCommand").is_some()
        }));

        assert_snapshot_task(
            &mut plugin,
            Task {
                data_type: 207,
                object_name: String::new(),
                data: String::new(),
                token: "acct".to_string(),
            },
            "acct",
            &[
                "win_user_sysuser_user",
                "win_user_sysuser_name",
                "win_user_sysuser_sid",
                "win_user_sysuser_flag",
            ],
        );

        let result = assert_snapshot_task(
            &mut plugin,
            Task {
                data_type: 208,
                object_name: String::new(),
                data: String::new(),
                token: "soft".to_string(),
            },
            "soft",
            &["win_user_softwareserver_flag"],
        );
        assert!(
            result.iter().any(|payload| {
                payload["win_user_softwareserver_flag"].as_str() == Some("1")
            })
                || result
                    .iter()
                    .any(|payload| payload["win_user_softwareserver_flag"].as_str() == Some("2"))
        );

        plugin.shutdown();
    }

    #[test]
    fn protocol_file_tasks_emit_records_and_ack() {
        let mut plugin = PluginHarness::new();
        let temp = std::env::temp_dir().join("wdriver-protocol-dir");
        let file = temp.join("sample.txt");
        fs::create_dir_all(&temp).expect("create temp dir");
        fs::write(&file, b"protocol-file-test").expect("write temp file");

        let directory_records = assert_snapshot_task(
            &mut plugin,
            Task {
                data_type: 209,
                object_name: String::new(),
                data: temp.to_string_lossy().into_owned(),
                token: "dir".to_string(),
            },
            "dir",
            &["win_user_driectinfo_flag"],
        );
        assert!(directory_records.iter().any(|payload| {
            payload["win_user_driectinfo_flag"].as_str() == Some("1")
        }));
        assert!(directory_records.iter().any(|payload| {
            payload["win_user_driectinfo_flag"].as_str() == Some("2")
                && payload["win_user_driectinfo_filename"].as_str() == Some("sample.txt")
        }));

        let file_records = assert_snapshot_task(
            &mut plugin,
            Task {
                data_type: 210,
                object_name: String::new(),
                data: file.to_string_lossy().into_owned(),
                token: "file".to_string(),
            },
            "file",
            &[
                "win_user_fileinfo_filename",
                "win_user_fileinfo_dwFileAttributes",
                "win_user_fileinfo_dwFileAttributesHide",
                "win_user_fileinfo_md5",
                "win_user_fileinfo_m_seFileSizeof",
                "win_user_fileinfo_seFileAccess",
                "win_user_fileinfo_seFileCreate",
                "win_user_fileinfo_seFileModify",
            ],
        );
        assert_eq!(
            file_records[0]["win_user_fileinfo_filename"].as_str(),
            Some("sample.txt")
        );
        assert!(!file_records[0]["win_user_fileinfo_md5"].as_str().unwrap_or("").is_empty());

        let _ = fs::remove_file(file);
        let _ = fs::remove_dir_all(temp);
        plugin.shutdown();
    }

    #[test]
    fn protocol_etw_tasks_emit_expected_categories() {
        let mut plugin = PluginHarness::new();
        for data_type in 300..=305 {
            let token = format!("etw-{}", data_type);
            plugin.send_task(&Task {
                data_type,
                object_name: String::new(),
                data: String::new(),
                token: token.clone(),
            });
            let ack = plugin.collect_until_ack(&token, Duration::from_secs(10)).ack;
            assert_eq!(ack_status(&ack), "success");
        }

        let _ = Command::new("cmd").args(["/C", "exit", "0"]).status();

        let process_record = plugin.collect_until_data_type(300, Duration::from_secs(10));
        let process_payload = parse_udata(&process_record);
        assert!(process_payload.get("win_etw_processinfo_pid").is_some());

        let thread_record = plugin.collect_until_data_type(301, Duration::from_secs(10));
        let thread_payload = parse_udata(&thread_record);
        assert!(thread_payload.get("win_etw_threadinfo_tid").is_some());

        let image_record = plugin.collect_until_data_type(302, Duration::from_secs(10));
        let image_payload = parse_udata(&image_record);
        assert!(image_payload.get("win_etw_imageinfo_fileName").is_some());

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("listener addr");
        let accept_thread = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept socket");
            let mut buf = [0u8; 8];
            let _ = socket.read(&mut buf);
        });
        let mut client = TcpStream::connect(addr).expect("connect loopback");
        let _ = client.write_all(b"etw");
        drop(client);
        let _ = accept_thread.join();

        let network_record = plugin.collect_until_data_type(303, Duration::from_secs(10));
        let network_payload = parse_udata(&network_record);
        assert!(network_payload.get("win_network_processid").is_some());
        assert!(network_payload.get("win_network_procespath").is_some());
        assert!(network_payload.get("win_network_processpathsize").is_some());
        if network_payload["win_network_addressfamily"].as_str() == Some("2") {
            assert!(
                network_payload["win_network_localaddr"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .all(|ch| ch.is_ascii_digit())
            );
            assert!(
                network_payload["win_network_remoteaddr"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .all(|ch| ch.is_ascii_digit())
            );
        }
        let process_path = network_payload["win_network_procespath"].as_str().unwrap_or("");
        let process_path_size = network_payload["win_network_processpathsize"]
            .as_str()
            .unwrap_or("0")
            .parse::<usize>()
            .unwrap_or(0);
        if !process_path.is_empty() {
            assert!(process_path_size > 0);
        }

        let _ = Command::new("reg")
            .args([
                "add",
                "HKCU\\Software\\wdriver-etw-test",
                "/v",
                "demo",
                "/t",
                "REG_SZ",
                "/d",
                "1",
                "/f",
            ])
            .status();
        let registry_record = plugin.collect_until_data_type(304, Duration::from_secs(10));
        let registry_payload = parse_udata(&registry_record);
        assert!(registry_payload.get("win_etw_regtab_eventname").is_some());

        let temp = std::env::temp_dir().join("wdriver-etw-file.txt");
        fs::write(&temp, b"file-io").expect("write etw file");
        let _ = fs::read(&temp);
        let file_record = plugin.collect_until_data_type(305, Duration::from_secs(10));
        let file_payload = parse_udata(&file_record);
        assert!(file_payload.get("win_etw_fileio_eventname").is_some());
        let _ = fs::remove_file(temp);
        let _ = Command::new("reg")
            .args(["delete", "HKCU\\Software\\wdriver-etw-test", "/f"])
            .status();

        plugin.shutdown();
    }

    #[test]
    fn protocol_repeated_etw_start_is_idempotent() {
        let mut plugin = PluginHarness::new();
        for token in ["etw-a", "etw-b"] {
            plugin.send_task(&Task {
                data_type: 300,
                object_name: String::new(),
                data: String::new(),
                token: token.to_string(),
            });
            let ack = plugin.collect_until_ack(token, Duration::from_secs(10)).ack;
            assert_eq!(ack_status(&ack), "success");
        }
        plugin.shutdown();
    }

    fn assert_snapshot_task(
        plugin: &mut PluginHarness,
        task: Task,
        token: &str,
        required_keys: &[&str],
    ) -> Vec<Value> {
        plugin.send_task(&task);
        let result = plugin.collect_until_ack(token, Duration::from_secs(20));
        assert_eq!(ack_status(&result.ack), "success");
        assert!(!result.records.is_empty());

        let payloads: Vec<Value> = result.records.iter().map(parse_udata).collect();
        for key in required_keys {
            assert!(payloads.iter().any(|payload| payload.get(*key).is_some()));
        }
        payloads
    }

    fn parse_udata(record: &wdriver::protocol::Record) -> Value {
        let payload = record
            .data
            .as_ref()
            .expect("record payload")
            .fields
            .get("udata")
            .expect("udata field");
        serde_json::from_str(payload).expect("parse udata")
    }
}
