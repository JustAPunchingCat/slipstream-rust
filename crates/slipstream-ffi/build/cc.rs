use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) fn resolve_cc(target: &str) -> String {
    if target.contains("android") {
        env::var("RUST_ANDROID_GRADLE_CC")
            .or_else(|_| env::var("CC"))
            .unwrap_or_else(|_| "cc".to_string())
    } else {
        env::var("CC").unwrap_or_else(|_| {
            if target.contains("msvc") {
                "cl".to_string()
            } else {
                "cc".to_string()
            }
        })
    }
}

pub(crate) fn resolve_ar(target: &str, cc: &str) -> String {
    if target.contains("android") {
        if let Ok(ar) = env::var("RUST_ANDROID_GRADLE_AR") {
            return ar;
        }
    }
    if let Ok(ar) = env::var("AR") {
        return ar;
    }
    if target.contains("msvc") {
        return "lib".to_string();
    }
    if let Some(dir) = Path::new(cc).parent() {
        let candidate = dir.join("llvm-ar");
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
        let candidate = dir.join("ar");
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    "ar".to_string()
}

pub(crate) fn create_archive(
    ar: &str,
    archive: &Path,
    objects: &[PathBuf],
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new(ar);
    if target.contains("msvc") {
        command.arg(format!("/OUT:{}", archive.display()));
        for obj in objects {
            command.arg(obj);
        }
    } else {
        command.arg("crus").arg(archive);
        for obj in objects {
            command.arg(obj);
        }
    }
    let status = command.status()?;
    if !status.success() {
        return Err("Failed to create static archive for slipstream objects.".into());
    }
    Ok(())
}

pub(crate) fn compile_c_file(
    cc: &str,
    source: &Path,
    output: &Path,
    include_dirs: &[&Path],
    flags: &[String],
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new(cc);

    if target.contains("msvc") {
        command.arg("/c");
        command.arg(format!("/Fo{}", output.display()));
    } else {
        command.arg("-c");
        command.arg("-fPIC");
        command.arg("-o").arg(output);
    }

    command.arg(source);

    for dir in include_dirs {
        if target.contains("msvc") {
            command.arg(format!("/I{}", dir.display()));
        } else {
            command.arg("-I").arg(dir);
        }
    }

    for flag in flags {
        command.arg(flag);
    }

    let status = command.status()?;
    if !status.success() {
        return Err(format!("Failed to compile {}.", source.display()).into());
    }
    Ok(())
}
