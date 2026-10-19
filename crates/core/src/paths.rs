use std::ffi::OsString;
use std::path::PathBuf;

/// Absolute fallback used when neither `XDG_DATA_HOME` nor `HOME` yields an absolute path.
const FALLBACK_DIR: &str = "/tmp/secret-guardian";

fn absolute(v: Option<OsString>) -> Option<PathBuf> {
    v.map(PathBuf::from).filter(|p| p.is_absolute())
}

fn data_dir_from(xdg_data_home: Option<OsString>, home: Option<OsString>) -> PathBuf {
    if let Some(d) = absolute(xdg_data_home) {
        return d.join("secret-guardian");
    }
    if let Some(h) = absolute(home) {
        return h.join(".local/share/secret-guardian");
    }
    PathBuf::from(FALLBACK_DIR)
}

fn socket_from(xdg_runtime_dir: Option<OsString>, data_dir: PathBuf) -> PathBuf {
    match absolute(xdg_runtime_dir) {
        Some(d) => d.join("secret-guardian.sock"),
        None => data_dir.join("sg.sock"),
    }
}

/// Always returns an absolute path: empty or relative `XDG_DATA_HOME`/`HOME` are ignored and
/// the last resort is `/tmp/secret-guardian`.
pub fn default_data_dir() -> PathBuf {
    data_dir_from(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))
}

/// Always returns an absolute path; empty or relative `XDG_RUNTIME_DIR` is ignored.
pub fn default_socket() -> PathBuf {
    socket_from(std::env::var_os("XDG_RUNTIME_DIR"), default_data_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    #[test]
    fn data_dir_prefers_xdg_then_home() {
        assert_eq!(
            data_dir_from(os("/x"), os("/h")),
            PathBuf::from("/x/secret-guardian")
        );
        assert_eq!(
            data_dir_from(None, os("/h")),
            PathBuf::from("/h/.local/share/secret-guardian")
        );
    }

    #[test]
    fn empty_or_relative_vars_are_ignored() {
        assert_eq!(
            data_dir_from(os(""), os("/h")),
            PathBuf::from("/h/.local/share/secret-guardian")
        );
        assert_eq!(
            data_dir_from(os("rel"), os("")),
            PathBuf::from(FALLBACK_DIR)
        );
        assert_eq!(data_dir_from(None, None), PathBuf::from(FALLBACK_DIR));
        assert_eq!(data_dir_from(None, os("")), PathBuf::from(FALLBACK_DIR));
    }

    #[test]
    fn socket_ignores_empty_runtime_dir() {
        let data = PathBuf::from("/d/secret-guardian");
        assert_eq!(
            socket_from(os("/run/user/1"), data.clone()),
            PathBuf::from("/run/user/1/secret-guardian.sock")
        );
        assert_eq!(socket_from(os(""), data.clone()), data.join("sg.sock"));
        assert_eq!(socket_from(None, data.clone()), data.join("sg.sock"));
        assert!(socket_from(None, data_dir_from(None, None)).is_absolute());
    }
}
