Subset of vectors from https://github.com/C2SP/CCTV/tree/main/ML-KEM/modulus
(only one input per algo)

<hr>

# Bad encapsulation keys

Section 6.2 of FIPS 203 ipd (ML-KEM Encapsulation) requires input validation on
the encapsulation key, checking that all encoded polynomial coefficients are
reduced modulo the field prime (the "Modulus check").

The files in the modulus/ folder provide invalid ML-KEM.Encaps inputs,
hex-encoded, one per line. Every value in the range q to 2¹²-1 and every
position in the key is tested individually.
