pragma circom 2.0.0;

template AgeGate() {
    /*
    Enforce that provided age is greater than or equal to public threshold age

    **SECURITY WARNING**:
    - This template is strictly designed for human age verification adhering to the macro protocol design
    - BOTH threshold and provided age size can't be over 255 AND
    - Public threshold MUST be validated by the verifier via public input before proof verification

    NOTE: poseidon hash commits to the provided age due to issuer trust.

    OPTIMISATION NOTE: For fewer constraints, ranges for providedAge and thresholdAge are left unconstrained,
    the architecture places 100% trust on the issuer and that the verifier will validate the public thresholdAge.
    */

    signal input providedAge;
    signal input thresholdAge;

    signal result;

    // Hardcode range limit
    // 8 bits: 0 to 255 age range; 9th bit reserved for holding truth value
    var range = 8;

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

    result <== (1 << range) + providedAge - thresholdAge;

    // Verify whether the 9th bit is 1
    signal resultBitArr[range + 1];

    var resultBitSum = 0;

    // Loop through all 9 bits (range)
    for (var i = 0; i <= range; i++) {
          resultBitArr[i] <-- (result >> i) & 1;

          // Binary lock (0,1) so resultBitSum has exactly 1 possible connection with result
          resultBitArr[i] * (resultBitArr[i] - 1) === 0;

          // Add the current bit weight to the bit sum if available
          resultBitSum += resultBitArr[i] * (1 << i);
    }

    // Verify whether the sum of the bits from the bitArr signal aligns with the original result signal
    // Proves that the magnitude is maintained within the 9 bit range
    resultBitSum === result;

    // Final threshold check: if provided age >= threshold age
    1 === resultBitArr[range];
}

// poseidon binding with provided age and signature here

component main {public [thresholdAge]} = AgeGate();
