# ZK Age Gate Protocol (Proof Of Concept / Demo)
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
[Protocol Coordinator] Routing age policy to Prover...
[Prover (INTERNAL)] Formatting inputs for native C++ witness generation...
[Prover (INTERNAL)] Executing native C++ witness and calculating Groth16 proof...
Generating witness for circuit age_gate
version: 2
n_sections: 2
section_id: 1
section_length: 40
n8: 32
q: 21888242871839275222246405745257275088548364400416034343698204186575808495617
n_witness_values: 619
section_id: 2
section_length: 19808
[Prover (INTERNAL)] Generated Proof!
[Protocol Coordinator] Routing Proof Package to Verifier...
ProofPackage {
    commitment: 2397097578686680303251667467448889017223025812099449787741671186613230729964,
    pk_p: 6805848725542031798,
    signature: ed25519::Signature {
        R: 0xcdfc1edf1a4a6a6c439f840b97fa43d094a3367f3b60d94ed08c1059854273d5,
        s: 0xec0d993362f256dc4444fd971eb7940066f3da3106973739c0a3774f14b6ea00,
    },
    proof: Proof {
        a: (2684869177825826913790247346541943651751174818215176547804670233914448961573, 10648403477127998811548448458282017753758399617753423429158579832325712891952),
        b: (QuadExtField(9625075983923189686757864853604821893952550972533167010663149354466190636539 + 15381359619674589150059409225449617473407796348372618413614469886130464862989 * u), QuadExtField(1987494064381506404576212145120314895856432762281950097404269595791946914202 + 10041570730658086589995494862321430430338956142341580487951107955004226457259 * u)),
        c: (714933946543271602316196012129050463127808270802030129611221566545503886908, 7942470363308138503158037049809774363531944140495673925344121480689148937418),
    },
}
[Verifier (INTERNAL)] Valid Commitment Signature!
[Verifier (INTERNAL)] Valid Proof!
[Protocol Coordinator] Proof valid: true
```
