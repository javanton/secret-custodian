use std::path::PathBuf;

pub fn default_data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(d).join("secret-guardian");
    }
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share/secret-guardian")
}

pub fn default_socket() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) => PathBuf::from(d).join("secret-guardian.sock"),
        None => default_data_dir().join("sg.sock"),
    }
}
