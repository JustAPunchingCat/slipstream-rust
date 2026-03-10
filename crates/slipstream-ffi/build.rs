#[path = "build/android.rs"]
mod android;
#[path = "build/cc.rs"]
mod cc_utils;
#[path = "build/openssl.rs"]
mod openssl;
#[path = "build/picoquic.rs"]
mod picoquic;
#[path = "build/util.rs"]
mod util;

use android::maybe_link_android_builtins;
use cc_utils::{compile_c_file, create_archive, resolve_ar};
use openssl::resolve_openssl_paths;
use picoquic::{
    build_picoquic, locate_picoquic_include_dir, locate_picoquic_lib_dir,
    locate_picotls_include_dir, resolve_picoquic_libs,
};
use std::env;
use std::path::{Path, PathBuf};
use util::env_flag;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PICOQUIC_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_BUILD_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PICOQUIC_AUTO_BUILD");
    println!("cargo:rerun-if-env-changed=PICOTLS_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_ROOT_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_CRYPTO_LIBRARY");
    println!("cargo:rerun-if-env-changed=OPENSSL_SSL_LIBRARY");
    println!("cargo:rerun-if-env-changed=OPENSSL_USE_STATIC_LIBS");
    println!("cargo:rerun-if-env-changed=OPENSSL_NO_VENDOR");
    println!("cargo:rerun-if-env-changed=DEP_OPENSSL_ROOT");
    println!("cargo:rerun-if-env-changed=DEP_OPENSSL_INCLUDE");
    println!("cargo:rerun-if-env-changed=RUST_ANDROID_GRADLE_CC");
    println!("cargo:rerun-if-env-changed=RUST_ANDROID_GRADLE_AR");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
    println!("cargo:rerun-if-env-changed=ANDROID_ABI");
    println!("cargo:rerun-if-env-changed=ANDROID_PLATFORM");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=AR");

    let openssl_paths = resolve_openssl_paths();
    let target = env::var("TARGET").unwrap_or_default();
    let cc_tool = cc_utils::resolve_cc(&target);
    let auto_build = env_flag("PICOQUIC_AUTO_BUILD", true);
    let explicit_picoquic_include = env::var_os("PICOQUIC_INCLUDE_DIR").is_some();
    let explicit_picoquic_lib = env::var_os("PICOQUIC_LIB_DIR").is_some();
    let explicit_picoquic_include_lib = explicit_picoquic_include || explicit_picoquic_lib;
    let mut picoquic_include_dir = locate_picoquic_include_dir();
    let mut picoquic_lib_dir = locate_picoquic_lib_dir();
    let mut picotls_include_dir = locate_picotls_include_dir();

    if auto_build
        && !explicit_picoquic_include_lib
        && (picoquic_include_dir.is_none() || picoquic_lib_dir.is_none())
    {
        build_picoquic(&openssl_paths, &target)?;
        picoquic_include_dir = locate_picoquic_include_dir();
        picoquic_lib_dir = locate_picoquic_lib_dir();
        picotls_include_dir = locate_picotls_include_dir();
    }

    if explicit_picoquic_include_lib {
        if picoquic_include_dir.is_none() {
            return Err(
                "Explicit PICOQUIC_INCLUDE_DIR/PICOQUIC_LIB_DIR set; missing headers. Set PICOQUIC_INCLUDE_DIR to match your libs."
                .into(),
            );
        }
        if picoquic_lib_dir.is_none() {
            return Err(
                "Explicit PICOQUIC_INCLUDE_DIR/PICOQUIC_LIB_DIR set; missing libs. Set PICOQUIC_LIB_DIR to match your headers."
                .into(),
            );
        }
    }

    let picoquic_include_dir = picoquic_include_dir.ok_or(
        "Missing picoquic headers; set PICOQUIC_DIR or PICOQUIC_INCLUDE_DIR (default: vendor/picoquic).",
    )?;
    let picoquic_lib_dir = picoquic_lib_dir.ok_or(
        "Missing picoquic build artifacts; run ./scripts/build_picoquic.sh or set PICOQUIC_BUILD_DIR/PICOQUIC_LIB_DIR.",
    )?;
    let picotls_include_dir = picotls_include_dir.ok_or(
        "Missing picotls headers; set PICOTLS_INCLUDE_DIR or build picoquic with PICOQUIC_FETCH_PTLS=ON.",
    )?;

    let ar_tool = resolve_ar(&target, &cc_tool);
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let cc_dir = manifest_dir.join("cc");

    let mut object_paths = Vec::new();
    let mut c_sources = vec![
        ("slipstream_server_cc.c", vec![&picoquic_include_dir as &Path]),
        ("slipstream_mixed_cc.c", vec![&picoquic_include_dir as &Path]),
        ("slipstream_poll.c", vec![&picoquic_include_dir as &Path]),
        ("slipstream_stateless_packet.c", vec![&picoquic_include_dir as &Path]),
        ("slipstream_test_helpers.c", vec![&picoquic_include_dir as &Path]),
        ("picotls_layout.c", vec![&picoquic_include_dir as &Path, &picotls_include_dir as &Path]),
    ];

    let wincompat_src = manifest_dir.join("src").join("wincompat.c");
    if target.contains("windows") {
        println!("cargo:rerun-if-changed={}", wincompat_src.display());
        c_sources.push(("wincompat.c", vec![&picoquic_include_dir as &Path]));
    }

    for (src_name, includes) in c_sources {
        let src_path = if src_name == "wincompat.c" {
            wincompat_src.clone()
        } else {
            cc_dir.join(src_name)
        };
        println!("cargo:rerun-if-changed={}", src_path.display());

        let obj_name = format!("{}.o", src_name);
        let obj_path = out_dir.join(obj_name);

        let mut flags = Vec::new();
        if target.contains("msvc") {
            flags.push("/D_WINDOWS".to_string());
            flags.push(format!("/FI{}", picoquic_include_dir.join("wincompat.h").display()));
            flags.push("/FIws2tcpip.h".to_string());
            flags.push("/D__attribute__(x)=".to_string());
            flags.push("/std:c11".to_string());
        }

        compile_c_file(&cc_tool, &src_path, &obj_path, &includes, &flags, &target)?;
        object_paths.push(obj_path);
    }

    let picoquic_internal = picoquic_include_dir.join("picoquic_internal.h");
    if picoquic_internal.exists() {
        println!("cargo:rerun-if-changed={}", picoquic_internal.display());
    }

    let archive = out_dir.join("libslipstream_ffi_c_objs.a");
    create_archive(&ar_tool, &archive, &object_paths, &target)?;
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=slipstream_ffi_c_objs");

    let picoquic_libs = resolve_picoquic_libs(&picoquic_lib_dir).ok_or(
        "Missing picoquic build artifacts; run ./scripts/build_picoquic.sh or set PICOQUIC_BUILD_DIR/PICOQUIC_LIB_DIR.",
    )?;
    for dir in picoquic_libs.search_dirs {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }
    for lib in picoquic_libs.libs {
        println!("cargo:rustc-link-lib=static={}", lib);
    }

    if !target.contains("android") && !target.contains("windows") {
        println!("cargo:rustc-link-lib=dylib=pthread");
    } else {
        maybe_link_android_builtins(&target, &cc_tool);
    }   

    if target.contains("msvc") {
        println!("cargo:rustc-link-lib=dylib=ws2_32");
        println!("cargo:rustc-link-lib=dylib=bcrypt");
        println!("cargo:rustc-link-lib=dylib=advapi32");
        println!("cargo:rustc-link-lib=dylib=userenv");
    }

    Ok(())
}
