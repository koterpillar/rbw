use directories::ProjectDirs;

use crate::prelude::*;

use std::{
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::PathBuf,
};

pub fn make_all() -> Result<()> {
    create_dir_all_with_permissions(&cache_dir()?, 0o700)?;
    create_dir_all_with_permissions(&runtime_dir()?, 0o700)?;
    create_dir_all_with_permissions(&data_dir()?, 0o700)?;

    Ok(())
}

fn create_dir_all_with_permissions(path: &std::path::Path, mode: u32) -> Result<()> {
    // ensure the initial directory creation happens with the correct mode,
    // to avoid race conditions
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    // but also make sure to forcibly set the mode, in case the directory
    // already existed
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|source| {
        Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        }
    })?;
    Ok(())
}

pub fn config_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.json"))
}

const INVALID_PATH: &percent_encoding::AsciiSet =
    &percent_encoding::CONTROLS.add(b'/').add(b'%').add(b':');

pub fn db_file(server: &str, email: &str) -> Result<PathBuf> {
    let server = percent_encoding::percent_encode(server.as_bytes(), INVALID_PATH).to_string();
    Ok(cache_dir()?.join(format!("{server}:{email}.json")))
}

pub fn pid_file() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("pidfile"))
}

pub fn agent_stdout_file() -> Result<PathBuf> {
    Ok(data_dir()?.join("agent.out"))
}

pub fn agent_stderr_file() -> Result<PathBuf> {
    Ok(data_dir()?.join("agent.err"))
}

pub fn device_id_file() -> Result<PathBuf> {
    Ok(data_dir()?.join("device_id"))
}

pub fn socket_file() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("socket"))
}

pub fn ssh_agent_socket_file() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("ssh-agent-socket"))
}

fn project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("", "", &profile()).ok_or(crate::error::Error::FailedToFindDataDirectory)
}

fn config_dir() -> Result<PathBuf> {
    Ok(project_dirs()?.config_dir().to_path_buf())
}

fn cache_dir() -> Result<PathBuf> {
    Ok(project_dirs()?.cache_dir().to_path_buf())
}

fn data_dir() -> Result<PathBuf> {
    Ok(project_dirs()?.data_dir().to_path_buf())
}

fn runtime_dir() -> Result<PathBuf> {
    Ok(project_dirs()?.runtime_dir().map_or_else(
        || {
            format!(
                "{}/{}-{}",
                std::env::temp_dir().to_string_lossy(),
                profile(),
                rustix::process::getuid().as_raw()
            )
            .into()
        },
        std::path::Path::to_path_buf,
    ))
}

pub fn profile() -> String {
    match std::env::var("RBW_PROFILE") {
        Ok(profile) if !profile.is_empty() => format!("rbw-{profile}"),
        _ => "rbw".to_string(),
    }
}
