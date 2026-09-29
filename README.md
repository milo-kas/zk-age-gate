# ZK Age Gate Protocol
> Languages: Rust, Circom 2.0

> Circuit: Range and bit constraints (built from scratch); poseidon commitment (circomlib)

This is a custom age verification protocol that places 100% trust on the issuer (a.k.a. KYC / Government). 

The prover's age is verified entirely via ZKP (Groth16 over BN254 with native C++ witness generation) and Ed25519 signature bound to a Poseidon hash for the commitment challenge

### Actors
- Prover: Generates ZKP with the signed age issued by trusted body.
- Issuer: The trusted body issuing and signing the prover's age.
- Verifier: Provides the threshold age requirement and verifies the provided signature and the ZK proof.

### Demo Output (Prover Age: 20, Threshold Age: 20):
```
[Protocol Coordinator] Starting protocol demo...
[Issuer (INTERNAL)] Initalising...
[Prover (INTERNAL)] Initalising...
[Prover (INTERNAL)] Packaging AgeRequest...
[Protocol Coordinator] Routing Age Request to Issuer...
[Issuer (INTERNAL)] Verifying ID: SOME_ID...
[Issuer (INTERNAL)] Packaging credentials...
[Protocol Coordinator] Routing Credential Package to Prover...
[Prover (INTERNAL)] Credential Package received!
[Prover (INTERNAL)] Storing Credential Package ...
[Verifier (INTERNAL)] Initalising...
[Verifier (INTERNAL)] Providing age requirement policy: age >= 20...
[Verifier (INTERNAL)] Issued nonce: 5924658673319725653
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
    commitment: 11450273149808713127007157438455693981100592968267073078844404525867391702252,
    pk_p: 17783746301780144681,
    signature: ed25519::Signature {
        R: 0xcad2b672687057ab427b4796071498872d80f3dba08836e68dc6d58a8d88d5d5,
        s: 0x30964ff4ba9b0752b6eaf57aeb98651e7203876aced0aa200b3bd4a80621a402,
    },
    proof: Proof {
        a: (153133045728936580293512054291902003917106294879568291020626118094808737115, 19791327158323009954290704757640152475535154116488794375427702372953482052484),
        b: (QuadExtField(12774052306661269770277574326523156922241121972652211071279467447276223098609 + 18628650235305140360524973029891785268192767312176430239988492603984193760422 * u), QuadExtField(8114734542760151201274354935927715557320077920260975639693289866458755111253 + 21630412759442955159611430457202647862233338337096791878036338500587894676844 * u)),
        c: (11623148684129514040164579164780417601419222580090809121032326906729709519879, 16280021199010846856398407381157432016145655241131498696324093530340977753614),
    },
}
[Verifier (INTERNAL)] Valid Commitment Signature!
[Verifier (INTERNAL)] Valid Proof!
[Protocol Coordinator] Routing Proof Validity to Prover...
[Prover (INTERNAL)] Received Access Decision: Granted
```
