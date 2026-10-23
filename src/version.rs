//! What `esp-mint --version` prints.

/// The lines of `--version`: the program and its version, then each library it
/// was built with that `Cargo.lock` locked (sp-wire, mint-core, air), one per
/// line as `name version`.
pub fn lines() -> Vec<String> {
    let mut out = vec![format!(
        "{} {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )];
    out.extend(
        env!("BUILT_WITH")
            .split(';')
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    );
    out
}
