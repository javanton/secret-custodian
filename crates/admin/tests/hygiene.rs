use std::path::Path;

fn rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn admin_never_references_reveal_for_injection() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![];
    rs_files(&src, &mut files);
    assert!(
        files.len() >= 7,
        "expected the admin sources, found {files:?}"
    );
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        assert!(
            !text.contains("reveal_for_injection"),
            "{} references reveal_for_injection",
            f.display()
        );
    }
}

#[test]
fn admin_does_not_log_request_uris() {
    // The login token is posted in a JSON body; no request-logging layer may exist anyway.
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![];
    rs_files(&src, &mut files);
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        assert!(
            !text.contains("TraceLayer"),
            "{} adds request tracing",
            f.display()
        );
    }
}
