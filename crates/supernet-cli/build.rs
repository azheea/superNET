//! Embed the app's built frontend (app/dist, `npm run build` in app/) for the
//! web console (`supernet --web`). Without it the binary still builds; the
//! console then says how to build the frontend.

use std::path::{Path, PathBuf};

fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, base, out);
        } else if let Ok(rel) = p.strip_prefix(base) {
            let rel = rel.to_string_lossy().replace('\\', "/");
            out.push((rel, p.canonicalize().unwrap_or(p)));
        }
    }
}

fn main() {
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../app/dist");
    println!("cargo:rerun-if-changed={}", dist.display());
    let mut files = Vec::new();
    walk(&dist, &dist, &mut files);
    files.sort();
    for (_, p) in &files {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    let mut code = String::from("pub static ASSETS: &[(&str, &[u8])] = &[\n");
    for (rel, p) in &files {
        code.push_str(&format!("    ({rel:?}, include_bytes!({:?})),\n", p.display().to_string()));
    }
    code.push_str("];\n");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("web_assets.rs");
    std::fs::write(out, code).expect("write web_assets.rs");
}
