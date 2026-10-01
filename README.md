# ZK Age Gate Protocol
> Languages: Rust, Circom 2.2+

> Circuit: Range and bit constraints (built from scratch); Poseidon commitment (circomlib)

This is a custom age verification protocol that places 100% trust on the issuer (a.k.a. KYC / Government). 

The prover's age is verified entirely via ZKP (Groth16 over BN254 with native C++ witness generation) and Ed25519 signature bound to a Poseidon hash for the commitment challenge.

### Actors
- Prover: Generates ZKP with the signed Poseidon commitment (hashed using the prover's age) issued by trusted body.
- Issuer: The trusted body issuing and signing the Poseidon commitment.
- Verifier: Provides the threshold age requirement with an ephemeral challenge nonce, and verifies the provided signature and the ZK proof.

## Quick Start
_**Requirements**: The only requirement is `Docker` with the `compose` plugin_

Clone & Setup
```bash
docker compose run --rm zk-env just setup
```
Run end-to-end simulation
```bash
docker compose run --rm zk-env just run
```
Run tests
```bash
docker compose run --rm zk-env just test
```

### Demo Output (Prover Age: 20, Threshold Age: 20):
```
[Protocol Coordinator] Starting protocol demo...
[Issuer (INTERNAL)] Initialising...
[Prover (INTERNAL)] Initialising...
[Prover (INTERNAL)] Packaging AgeRequest...
[Protocol Coordinator] Routing Age Request to Issuer...
[Issuer (INTERNAL)] Verifying ID: SOME_ID...
[Issuer (INTERNAL)] Packaging credentials...
[Protocol Coordinator] Routing Credential Package to Prover...
[Prover (INTERNAL)] Credential Package received!
[Prover (INTERNAL)] Storing Credential Package ...
[Verifier (INTERNAL)] Initialising...
[Verifier (INTERNAL)] Providing age requirement policy: age >= 20...
[Verifier (INTERNAL)] Issued nonce: 13535666713248680844
[Protocol Coordinator] Routing age policy & nonce to Prover...
[Prover (INTERNAL)] Formatting inputs for native C++ witness generation...
[Prover (INTERNAL)] Executing native C++ witness and calculating Groth16 proof...
Generating witness for circuit age_gate
version: 2
n_sections: 2
section_id: 1
section_length: 40
n8: 32
q: 21888242871839275222246405745257275088548364400416034343698204186575808495617
n_witness_values: 621
section_id: 2
section_length: 19872
[Prover (INTERNAL)] Generated Proof!
[Protocol Coordinator] Routing Proof Package to Verifier...
ProofPackage {
    commitment: 21190891962167541213014566999848590086161397653616068281713049622146100472510,
    pk_p: 8777420680508795639,
    signature: ed25519::Signature {
        R: 0x03bdf0e6ec299810117128c35d561fda26570a92c630bd5fcdf17807511b0aa5,
        s: 0xbd8d3f056e4c8ff1fce16ceada3dbd4f6e8c1286847e6c612d124572f4a29b0c,
    },
    proof: Proof {
        a: (19690010966158607792471355903751920955641716573041710429933396339923509728241, 8899322238749815350390034185689699174539986707869290311254042948288571086619),
        b: (QuadExtField(11177764809556990731215134595747984495017653419408431532033011268760240813641 + 17343718314893693603042556582927821331844948175374332545982311966878443674316 * u), QuadExtField(3837775727743471145102952902079200374466902180682276837599970382500904053025 + 12847802267900784595582297429634455552522092023431198896500072734076540988535 * u)),
        c: (5670269595221411455404144621583929750482398102962666899027441575471995876224, 1081582602161234630161844251941647788398504459804946072398896160840828395603),
    },
}
[Verifier (INTERNAL)] Valid Commitment Signature!
[Verifier (INTERNAL)] Valid Proof!
[Protocol Coordinator] Routing Proof Validity to Prover...
[Prover (INTERNAL)] Received Access Decision: Granted

```
