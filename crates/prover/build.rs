use std::env;

fn main() {
    // Use circuits dir instead of the crate dir for a path from root
    let circuit_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("Cargo failed at CARGO_MANIFEST_DIR")
        .replace("crates/prover", "circuits/build/age_gate_cpp");

    witnesscalc_adapter::build_and_link(&circuit_dir);

    // Rerun build.rs only if the C++ circuit files change
    println!("cargo:rerun-if-changed={}", circuit_dir);
}
