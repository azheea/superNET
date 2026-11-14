//! `zig cc` / `zig ar` as a C compiler, linker and archiver for cross builds.
//!
//! Rust's `cc` crate and rustc pass Rust target names (`--target=x86_64-unknown-linux-musl`)
//! that Zig does not understand, so they are dropped and Zig's own target
//! (`SUPERNET_ZIG_TARGET`, e.g. `x86_64-linux-musl`) is used instead. Named
//! `*ar*` the wrapper runs `zig ar`, otherwise `zig cc`. `SUPERNET_ZIG` is
//! the path of zig.exe.
//!
//! Long link lines arrive as a GNU response file (`@path`, one escaped
//! argument per line); it is expanded, filtered and written back for Zig.

use std::process::{exit, Command};

/// Split a GNU-style response file: whitespace separates arguments, a
/// backslash escapes the next character, quotes group.
fn parse_response(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut quote: Option<char> = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match (c, quote) {
            ('\\', _) => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    has = true;
                }
            }
            ('"' | '\'', None) => {
                quote = Some(c);
                has = true;
            }
            (q, Some(open)) if q == open => quote = None,
            (w, None) if w.is_whitespace() => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            (other, _) => {
                cur.push(other);
                has = true;
            }
        }
    }
    if has {
        out.push(cur);
    }
    out
}

fn escape(arg: &str) -> String {
    let mut s = String::with_capacity(arg.len() + 2);
    for c in arg.chars() {
        if c == '\\' || c == ' ' || c == '"' || c == '\'' || c == '\t' {
            s.push('\\');
        }
        s.push(c);
    }
    s
}

fn main() {
    let zig = std::env::var("SUPERNET_ZIG").unwrap_or_else(|_| "zig".into());
    let me = std::env::current_exe().ok().and_then(|p| p.file_stem().map(|s| s.to_string_lossy().to_lowercase())).unwrap_or_default();
    let mut cmd = Command::new(zig);
    if me.ends_with("-ar") || me == "ar" {
        cmd.arg("ar").args(std::env::args().skip(1));
    } else {
        let target = std::env::var("SUPERNET_ZIG_TARGET").unwrap_or_else(|_| "x86_64-linux-musl".into());
        // Expand response files so every argument can be filtered.
        let mut raw = Vec::new();
        for a in std::env::args().skip(1) {
            match a.strip_prefix('@').and_then(|p| std::fs::read_to_string(p).ok()) {
                Some(text) => raw.extend(parse_response(&text)),
                None => raw.push(a),
            }
        }
        let no_sysroot = std::env::var("SUPERNET_ZIG_NO_SYSROOT").is_ok_and(|v| v == "1");
        let mut args = Vec::new();
        let mut sdk_include: Option<String> = None;
        let mut it = raw.into_iter();
        while let Some(a) = it.next() {
            if a.starts_with("--target=") {
                continue;
            }
            if a == "-target" || a == "--target" {
                it.next();
                continue;
            }
            // SUPERNET_ZIG_NO_SYSROOT=1: compile-only checks of other Apple targets
            // (iOS) with Zig's own Darwin headers, without an Apple SDK.
            if no_sysroot && a == "-isysroot" {
                it.next();
                continue;
            }
            if no_sysroot && (a.starts_with("-mios-version-min") || a.starts_with("-miphoneos-version-min") || a.starts_with("-mtargetos=")) {
                continue;
            }
            // Zig's macOS stubs have libSystem but no libiconv; Rust's std asks for
            // it on Apple targets without needing any of its symbols here.
            if a == "-liconv" && target.contains("macos") {
                continue;
            }
            // A real Apple SDK (iOS: SDKROOT from a Mac's Xcode): Zig compiles with
            // -nostdsysteminc, so the SDK's headers must be named explicitly.
            if a == "-isysroot" && (target.contains("ios") || target.contains("macos")) {
                if let Some(sdk) = it.next() {
                    sdk_include = Some(format!("{sdk}/usr/include"));
                    args.push(a);
                    args.push(sdk);
                }
                continue;
            }
            args.push(a);
        }
        // Links name no sysroot; SDKROOT (set by the caller) says where the SDK is.
        if sdk_include.is_none() && (target.contains("ios") || target.contains("macos")) && !no_sysroot {
            sdk_include = std::env::var("SDKROOT").ok().map(|s| format!("{s}/usr/include"));
        }
        if let Some(inc) = sdk_include.filter(|p| std::path::Path::new(p).join("TargetConditionals.h").exists()) {
            let compile_only = args.iter().any(|a| a == "-c");
            if compile_only {
                args.push("-isystem".into());
                args.push(inc);
            } else if target.contains("ios") {
                // Only the static library is used on iOS (Apple's linker links it
                // into the app on a Mac). The links that do reach this wrapper are
                // dependencies' own cdylibs (boringtun, tun-rs), which cargo builds
                // and nothing uses; Zig has no iOS libSystem, so leave their system
                // symbols to the loader instead of failing.
                args.retain(|a| !a.starts_with("-l"));
                args.push("-Wl,-undefined,dynamic_lookup".into());
            } else {
                // macOS with a real SDK (the GUI app): its frameworks' .tbd stubs
                // (AppKit, WebKit, ...) and libraries.
                let sdk = inc.trim_end_matches("/usr/include").to_string();
                args.push(format!("-F{sdk}/System/Library/Frameworks"));
                args.push(format!("-L{sdk}/usr/lib"));
            }
        }
        cmd.arg("cc").arg("-target").arg(&target);
        // Hand long lines back to Zig as a response file (Windows limits command lines).
        if args.iter().map(|a| a.len() + 1).sum::<usize>() > 8000 {
            let path = std::env::temp_dir().join(format!("zigcc-{}.rsp", std::process::id()));
            let body: Vec<String> = args.iter().map(|a| escape(a)).collect();
            if std::fs::write(&path, body.join("\n")).is_ok() {
                cmd.arg(format!("@{}", path.display()));
                let status = cmd.status();
                let _ = std::fs::remove_file(&path);
                finish(status);
            }
        }
        cmd.args(args);
    }
    finish(cmd.status());
}

fn finish(status: std::io::Result<std::process::ExitStatus>) -> ! {
    match status {
        Ok(s) => exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("zigcc: {e}");
            exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{escape, parse_response};

    #[test]
    fn response_files_round_trip() {
        let args = ["-o", r"C:\a b\out.dylib", "-liconv", "x\"y"];
        let text: Vec<String> = args.iter().map(|a| escape(a)).collect();
        assert_eq!(parse_response(&text.join("\n")), args);
        assert_eq!(parse_response("\"C:\\\\x y\"\n-lm"), vec!["C:\\x y".to_string(), "-lm".to_string()]);
    }
}
