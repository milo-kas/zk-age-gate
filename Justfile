# This file is executed INSIDE the zk-env Docker container

_prepare:
    npm --prefix circuits install
    mkdir -p circuits/build

# Generate Powers of Tau locally
gen-ptau: _prepare
    snarkjs powersoftau new bn128 12 circuits/build/pot12_0000.ptau -v
    snarkjs powersoftau contribute circuits/build/pot12_0000.ptau circuits/build/pot12_0001.ptau --name="test" -v -e="idk"
    snarkjs powersoftau prepare phase2 circuits/build/pot12_0001.ptau circuits/build/pot12_final.ptau -v
    rm -f circuits/build/pot12_0000.ptau circuits/build/pot12_0001.ptau

# Compile circuit
compile-circuit: _prepare
    circom circuits/src/age_gate.circom --r1cs --c -l circuits/node_modules -o circuits/build

# Crypto Setup
setup-zkey:
    snarkjs groth16 setup circuits/build/age_gate.r1cs circuits/build/pot12_final.ptau circuits/build/age_gate_0000.zkey
    snarkjs zkey contribute circuits/build/age_gate_0000.zkey circuits/build/age_gate.zkey --name="test" -v -e="idk"

# Rust
build:
    cargo build

run:
    cargo r

test:
    cargo test

check:
    cargo check

# Setup
setup: gen-ptau compile-circuit setup-zkey build