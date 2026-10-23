//! Records the versions of the libraries this build locked (from `Cargo.lock`)
//! for `esp-mint --version`.

#[path = "src/lockfile.rs"]
mod lockfile;

fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");
    let lock = std::fs::read_to_string("Cargo.lock").unwrap_or_default();
    let built_with: Vec<String> = lockfile::versions(&lock, &["sp-wire", "mint-core", "air"])
        .into_iter()
        .map(|(name, version)| format!("{name} {version}"))
        .collect();
    println!("cargo:rustc-env=BUILT_WITH={}", built_with.join(";"));
}
