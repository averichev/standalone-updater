fn main() {
    // Used by the independent example only. Consumers supply their own build target.
    println!(
        "cargo:rustc-env=UPDATER_EXAMPLE_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
    println!("cargo:rerun-if-changed=build.rs");
}
