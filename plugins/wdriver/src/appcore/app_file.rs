use std::{fs, io::Read, path::Path, time::SystemTime};

use chrono::{DateTime, Local};

use crate::appcore::app_include::{AppDriectInfo, AppFileExInfo, AppFileInfo};

pub struct AppFile;

impl AppFile {
    const MAX_DIRECTORY_FILES: usize = 0x4090;

    pub fn get_directory_info(path: &str) -> Option<AppDriectInfo> {
        let root = Path::new(path);
        if !root.is_dir() {
            return None;
        }

        let mut files = Vec::new();
        let mut total_size: u64 = 0;
        Self::walk_directory(root, &mut files, &mut total_size);

        if files.is_empty() {
            return None;
        }

        Some(AppDriectInfo {
            directname: root.to_string_lossy().into_owned(),
            directsize: total_size.min(u32::MAX as u64) as u32,
            filecount: files.len().min(u32::MAX as usize) as u32,
            file_array: files,
        })
    }

    pub fn get_file_info(path: &str) -> Option<AppFileExInfo> {
        let path = Path::new(path);
        let metadata = fs::metadata(path).ok()?;
        if !metadata.is_file() {
            return None;
        }

        Some(AppFileExInfo {
            filename: path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            filecreate: format_system_time(metadata.created().ok()),
            filemodify: format_system_time(metadata.modified().ok()),
            fileaccess: format_system_time(metadata.accessed().ok()),
            fileattributes: file_attribute_text(&metadata),
            filesize: format_file_size(metadata.len()),
            fileattributes_hide: if is_hidden(path) {
                "隐藏 ".to_string()
            } else {
                String::new()
            },
            filepath: path.to_string_lossy().into_owned(),
            filemd5: md5_file(path).unwrap_or_default(),
        })
    }

    fn walk_directory(path: &Path, files: &mut Vec<AppFileInfo>, total_size: &mut u64) {
        if files.len() >= Self::MAX_DIRECTORY_FILES {
            return;
        }

        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            if files.len() >= Self::MAX_DIRECTORY_FILES {
                return;
            }

            let entry_path = entry.path();
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            if metadata.is_dir() {
                Self::walk_directory(&entry_path, files, total_size);
                continue;
            }

            if !metadata.is_file() {
                continue;
            }

            let size = metadata.len();
            *total_size = total_size.saturating_add(size);
            files.push(AppFileInfo {
                filesize: size.min(u32::MAX as u64) as u32,
                filename: entry_path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                filepath: entry_path.to_string_lossy().into_owned(),
            });
        }
    }
}

fn format_system_time(value: Option<SystemTime>) -> String {
    value
        .map(|time| {
            let datetime: DateTime<Local> = time.into();
            datetime.format("%Y/%m/%d %H:%M:%S").to_string()
        })
        .unwrap_or_default()
}

fn format_file_size(size: u64) -> String {
    if size > 1024 * 1024 * 1024 {
        format!("{:.2}GB", size as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if size > 1024 * 1024 {
        format!("{:.2}MB", size as f64 / 1024.0 / 1024.0)
    } else {
        format!("{:.2}KB", size as f64 / 1024.0)
    }
}

#[cfg(windows)]
fn file_attribute_text(metadata: &fs::Metadata) -> String {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes().to_string()
}

#[cfg(not(windows))]
fn file_attribute_text(_metadata: &fs::Metadata) -> String {
    String::new()
}

fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .map(|name| name.to_string_lossy().starts_with('.'))
        .unwrap_or(false)
}

fn md5_file(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut ctx = md5::Context::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let read = file.read(&mut buf).ok()?;
        if read == 0 {
            break;
        }
        ctx.consume(&buf[..read]);
    }

    Some(format!("{:x}", ctx.compute()))
}
