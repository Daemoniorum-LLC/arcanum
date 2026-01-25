fn main() {
    // CUDA linking (when cuda feature is enabled)
    if std::env::var("CARGO_FEATURE_CUDA").is_ok() {
        // Look for libblake3_cuda.so in the src directory
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let cuda_lib_path = format!("{}/src", manifest_dir);

        println!("cargo:rustc-link-search=native={}", cuda_lib_path);
        println!("cargo:rustc-link-lib=dylib=blake3_cuda");

        // Also check if library exists and warn if not
        let lib_path = format!("{}/libblake3_cuda.so", cuda_lib_path);
        if !std::path::Path::new(&lib_path).exists() {
            println!(
                "cargo:warning=CUDA library not found at {}. Build it with:",
                lib_path
            );
            println!(
                "cargo:warning=nvcc -O3 -arch=sm_89 --shared --compiler-options '-fPIC' blake3_cuda.cu -o libblake3_cuda.so"
            );
        }

        // Tell Cargo to re-run if the library changes
        println!("cargo:rerun-if-changed={}", lib_path);
    }

    // Re-run if build.rs changes
    println!("cargo:rerun-if-changed=build.rs");
}
