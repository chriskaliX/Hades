use std::collections::HashMap;

use serde_json::{json, Value};
use wdriver::{
    appcore::{
        app_account::AppAccount, app_autostart::AppAutoStart, app_net::AppNetwork,
        app_process::AppProcess, app_service_software::AppServiceSoftWare,
    },
    protocol::{Payload, Record, Task},
    transport::{unix_timestamp, Client},
};

fn main() {
    let mut client = Client::new();
    loop {
        let task = match client.receive_task() {
            Ok(task) => task,
            Err(_) => break,
        };

        if task.data_type == 0 {
            let _ = send_task_ack(&mut client, &task.token, "success", "");
            break;
        }

        let result = dispatch_task(&mut client, &task);
        match result {
            Ok(count) => {
                let msg = format!("{} records", count);
                let _ = send_task_ack(&mut client, &task.token, "success", &msg);
            }
            Err(err) => {
                let _ = send_task_ack(&mut client, &task.token, "failed", &err);
            }
        }
    }
}

fn dispatch_task(client: &mut Client, task: &Task) -> Result<usize, String> {
    match task.data_type {
        200 => collect_process(client),
        202 => collect_autostart(client),
        203 => collect_network(client),
        207 => collect_account(client),
        208 => collect_software(client),
        _ => Err(format!("unsupported task {}", task.data_type)),
    }
}

fn collect_process(client: &mut Client) -> Result<usize, String> {
    let mut items = Vec::new();
    if !AppProcess::get_process_info(&mut items) {
        return Err("process collection returned no data".to_string());
    }
    let mut count = 0;
    for item in items {
        send_windows_json(
            client,
            200,
            json!({
                "win_user_process_pid": item.pid.to_string(),
                "win_user_process_pribase": item.priclassbase,
                "win_user_process_thrcout": item.threadcount.to_string(),
                "win_user_process_parenid": item.th32parentprocessid.to_string(),
                "win_user_process_Path": item.processfullpath,
                "win_user_process_szExeFile": item.exefile,
            }),
        )?;
        count += 1;
    }
    Ok(count)
}

fn collect_autostart(client: &mut Client) -> Result<usize, String> {
    let mut items = Vec::new();
    if !AppAutoStart::get_astart_register(&mut items) {
        return Err("autostart collection returned no data".to_string());
    }
    let mut count = 0;
    for item in items {
        send_windows_json(
            client,
            202,
            json!({
                "win_user_autorun_flag": "1",
                "win_user_autorun_regName": item.valuename,
                "win_user_autorun_regKey": item.valuekey,
            }),
        )?;
        count += 1;
    }
    Ok(count)
}

fn collect_network(client: &mut Client) -> Result<usize, String> {
    let mut items = Vec::new();
    if !AppNetwork::get_socket_info(&mut items) {
        return Err("network collection returned no data".to_string());
    }
    let mut count = 0;
    for item in items {
        let is_tcp = item.protocol.eq_ignore_ascii_case("TCP");
        let src = format!("{}:{}", item.localaddress, item.localport);
        let dst = if is_tcp {
            format!("{}:{}", item.remoteaddress, item.remoteport)
        } else {
            String::new()
        };
        send_windows_json(
            client,
            203,
            json!({
                "win_user_net_flag": if is_tcp { "1" } else { "2" },
                "win_user_net_src": src,
                "win_user_net_dst": dst,
                "win_user_net_status": item.state,
                "win_user_net_pid": item.pid.to_string(),
            }),
        )?;
        count += 1;
    }
    Ok(count)
}

fn collect_account(client: &mut Client) -> Result<usize, String> {
    let mut items = Vec::new();
    if !AppAccount::get_account_info(&mut items) {
        return Err("account collection returned no data".to_string());
    }
    let mut count = 0;
    for item in items {
        send_windows_json(
            client,
            207,
            json!({
                "win_user_sysuser_user": item.serveruser,
                "win_user_sysuser_name": item.servername,
                "win_user_sysuser_sid": item.serverusid,
                "win_user_sysuser_flag": item.serverflag.to_string(),
            }),
        )?;
        count += 1;
    }
    Ok(count)
}

fn collect_software(client: &mut Client) -> Result<usize, String> {
    let mut items = Vec::new();
    if !AppServiceSoftWare::get_software_info(&mut items) {
        return Err("software collection returned no data".to_string());
    }
    let mut count = 0;
    for item in items {
        send_windows_json(
            client,
            208,
            json!({
                "win_user_softwareserver_flag": "2",
                "win_user_software_lpsName": item.name,
                "win_user_software_Size": item.size,
                "win_user_software_Ver": item.version,
                "win_user_software_installpath": item.insatllpath,
                "win_user_software_uninstallpath": item.uninstallpath,
                "win_user_software_data": "",
                "win_user_software_venrel": item.venrel,
            }),
        )?;
        count += 1;
    }
    Ok(count)
}

fn send_windows_json(client: &mut Client, data_type: i32, value: Value) -> Result<(), String> {
    let udata = serde_json::to_string(&value).map_err(|err| err.to_string())?;
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
    client.send_record(&rec).map_err(|err| err.to_string())
}

fn send_task_ack(client: &mut Client, token: &str, status: &str, msg: &str) -> Result<(), String> {
    if token.is_empty() {
        return Ok(());
    }
    let rec = Record {
        data_type: 5100,
        timestamp: unix_timestamp(),
        data: Some(Payload {
            fields: HashMap::from([
                ("token".to_string(), token.to_string()),
                ("status".to_string(), status.to_string()),
                ("msg".to_string(), msg.to_string()),
            ]),
        }),
    };
    client.send_record(&rec).map_err(|err| err.to_string())
}
