use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    // CUDA compilation and linking (when cuda feature is enabled)
    if env::var("CARGO_FEATURE_CUDA").is_ok() {
        build_cuda();
    }

    // Re-run if build.rs changes
    println!("cargo:rerun-if-changed=build.rs");
}

fn build_cuda() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let cu_src = format!("{}/src/blake3_cuda.cu", manifest_dir);
    let lib_output = format!("{}/libblake3_cuda.so", out_dir);

    // Re-run if the CUDA source changes
    println!("cargo:rerun-if-changed={}", cu_src);

    // Check if .cu source exists
    if !Path::new(&cu_src).exists() {
        println!("cargo:warning=CUDA source not found: {}", cu_src);
        println!("cargo:warning=CUDA feature enabled but blake3_cuda.cu is missing");
        return;
    }

    // Detect compute capability: allow override via CUDA_ARCH env var
    // Defaults to sm_75 for broad Turing+ GPU support (RTX 2000+)
    let arch = env::var("CUDA_ARCH").unwrap_or_else(|_| "sm_75".to_string());
    println!("cargo:rerun-if-env-changed=CUDA_ARCH");

    // Try to compile with nvcc
    let nvcc_result = Command::new("nvcc")
        .args([
            "-O3",
            &format!("-arch={}", arch),
            "--shared",
            "--compiler-options",
            "-fPIC",
            &cu_src,
            "-o",
            &lib_output,
        ])
        .output();

    match nvcc_result {
        Ok(output) if output.status.success() => {
            // nvcc compiled successfully — link against the built library
            println!("cargo:rustc-link-search=native={}", out_dir);
            println!("cargo:rustc-link-lib=dylib=blake3_cuda");
        }
        Ok(output) => {
            // nvcc ran but failed — emit warnings with stderr
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("cargo:warning=nvcc compilation failed (exit code: {:?})", output.status.code());
            for line in stderr.lines().take(10) {
                println!("cargo:warning=nvcc: {}", line);
            }
            println!("cargo:warning=CUDA acceleration will not be available");

            // Fall back to pre-built library if available
            link_prebuilt_cuda(&manifest_dir, &out_dir);
        }
        Err(e) => {
            // nvcc not found — emit a warning and try pre-built fallback
            println!("cargo:warning=nvcc not found ({}). Install CUDA toolkit for GPU acceleration.", e);
            println!("cargo:warning=Set CUDA_ARCH=sm_XX to target a specific GPU architecture.");

            // Fall back to pre-built library if available
            link_prebuilt_cuda(&manifest_dir, &out_dir);
        }
    }
}

/// Try to link against a pre-built libblake3_cuda.so in the source directory.
/// This supports the previous manual build workflow as a fallback.
fn link_prebuilt_cuda(manifest_dir: &str, out_dir: &str) {
    let prebuilt = format!("{}/src/libblake3_cuda.so", manifest_dir);
    if Path::new(&prebuilt).exists() {
        println!("cargo:warning=Using pre-built CUDA library: {}", prebuilt);
        println!("cargo:rustc-link-search=native={}/src", manifest_dir);
        println!("cargo:rustc-link-lib=dylib=blake3_cuda");
    } else {
        // No library available at all — the build will fail at link time
        // if any code actually calls the CUDA FFI functions. Emit the
        // link directives anyway so the error message is clear.
        println!("cargo:warning=No CUDA library available. Build manually with:");
        println!(
            "cargo:warning=  nvcc -O3 -arch=sm_75 --shared --compiler-options '-fPIC' \
             {}/src/blake3_cuda.cu -o {}/libblake3_cuda.so",
            manifest_dir, out_dir
        );
        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=dylib=blake3_cuda");
    }
}
