use std::path::PathBuf;
use log::LevelFilter;

pub fn init_log(curr_path: &PathBuf) -> bool {
    let debug_mode = {
        let test_meta = curr_path.join("test");
        test_meta.exists()
    };

    {
        let _ = std::fs::create_dir_all(curr_path.join("log"));
        let log_file = curr_path.join("log/wdriver.log");
        //clean
        if let Ok(mt) = std::fs::metadata(&log_file) {
            if mt.len() > 10 * 1024 * 1024 {
                //rename
                let log_file_old = curr_path.join("log/wdriver.log.old");
                let _ = std::fs::remove_file(&log_file_old);
                let _ = std::fs::rename(&log_file, &log_file_old);
            }
        }

        let fern_log_file = fern::log_file(log_file);
        if fern_log_file.is_err() {
            eprintln!("log file error:{:?}", fern_log_file.unwrap_err());
            return debug_mode;
        }
        let log_res = fern::Dispatch::new()
            .format(|out, message, record| {
                out.finish(format_args!(
                    "{} [{}] {}:{} {}",
                    chrono::Local::now().format("[%Y-%m-%d %H:%M:%S.%6f]"),
                    record.level(),
                    record.target(),
                    record.line().unwrap_or_default(),
                    message
                ))
            })
            // .level(if debug_mode {
            //     LevelFilter::Debug
            // } else {
            //     LevelFilter::Info
            // })
            .level(LevelFilter::Debug)
            .chain(fern_log_file.unwrap())
            .apply();
        if log_res.is_err() {
            eprintln!("fern log error:{:?}", log_res.unwrap_err());
        }
    }

    log::info!("------------------------------------------------------------------");
    log::info!("process path:{:?} client version:{}", curr_path, version::version!());

    debug_mode
}
