pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template AgeGate() {
    /*
    Enforce that the DoB epoch is lower than or equal to public DoB cutoff epoch.
    - Equivalent to enforcing that Prover's Age is greater than or equal to the Age threshold policy.

    **SECURITY CONSIDERATION**:
    - This template is strictly designed for human age verification adhering to the macro protocol design
    - BOTH threshold and DoB epoch size must be less than 2^32
    - Public threshold MUST be validated by the verifier via public input before proof verification

    NOTE: poseidon hash commits to the provided DoB epoch due to issuer trust.

    OPTIMISATION NOTE: For fewer constraints, ranges for dobEpoch and thresholdEpoch are left unconstrained,
    the architecture places 100% trust on the issuer and that the verifier will validate the public thresholdEpoch.
    */

    signal input dobEpoch;
    signal input thresholdEpoch;

    signal result;

    // (8 bit range for STATIC AGES calculation example)
    // 8 bits: 0 to 255 age range; 9th bit reserved for holding truth value

    // e.g. providedAge = 10, thresholdAge = 20
    // 1 << range = 1 0000 0000
    // 10 = 0 0000 1010
    // 20 = 0 0001 0100
    // thus:
    //   1 0000 0000 // range
    // + 0 0000 1010 // providedAge
    // - 0 0001 0100 // thresholdAge
    // = 0 1111 0110 // result
    // The 9th bit = 0, 10 did not absorb 20, it's lower than threshold

    // DoB Epoch:
    // Actual uses 33 bits (+1 bit for range condition) due to epoch schema (using days since a schema-defined date)
    // An older person was born earlier, thus SMALLER day count
    // thresholdEpoch >= dobEpoch to satisfy a greater age threshold

    var range = 32;

    result <== (1 << range) + thresholdEpoch - dobEpoch;

    // Verify whether the 33rd bit is 1
    signal resultBitArr[range + 1];

    var resultBitSum = 0;

    // Loop through all 33 bits
    for (var i = 0; i <= range; i++) {
          resultBitArr[i] <-- (result >> i) & 1;

          // Binary lock (0,1) so resultBitSum has exactly 1 possible connection with result
          resultBitArr[i] * (resultBitArr[i] - 1) === 0;

          // Add the current bit weight to the bit sum if available
          resultBitSum += resultBitArr[i] * (1 << i);
    }

    // Verify whether the sum of the bits from the bitArr signal aligns with the original result signal
    // Proves that the magnitude is maintained within the 33 bit range
    resultBitSum === result;

    // Final threshold check: if provided epoch <= threshold epoch
    1 === resultBitArr[range];
}

template AgeCommitmentGate() {
    /*
    Age and poseidon wrapper

    Public inputs:
    thresholdEpoch, issuerCommitment
    pk_p -- Prover's public key (pk)
    nonce

    Private inputs:
    salt, dobEpoch
    */

    // public inputs
    signal input thresholdEpoch;
    signal input issuerCommitment;
    signal input pk_p;

    // Nonce (prevent replay attacks)
    signal input nonce;
    signal satisfyCompiler;
    satisfyCompiler <== nonce * nonce;

    // private inputs
    signal input dobEpoch;
    signal input salt;

    // Generate poseidon hash with private DoB epoch + salt + pk_p
    component hasher = Poseidon(3);
    hasher.inputs[0] <== dobEpoch;
    hasher.inputs[1] <== salt;
    hasher.inputs[2] <== pk_p;

    // Verify the hash containing the DoB epoch + salt + pk_p matches public hash signed by issuer
    hasher.out === issuerCommitment;

    component ageGate = AgeGate();

    // As the provided DoB epoch was proven to not be altered, wire it into the AgeGate
    ageGate.dobEpoch <== dobEpoch;
    // Public input can safely be wired, burden is on verifier outside the circuit
    ageGate.thresholdEpoch <== thresholdEpoch;
}

// Run main age gate circuit with commitment and age binding.
component main {public [thresholdEpoch, issuerCommitment, pk_p, nonce]} = AgeCommitmentGate();
