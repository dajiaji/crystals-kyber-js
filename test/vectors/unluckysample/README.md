Vectors from https://github.com/C2SP/CCTV/tree/main/ML-KEM/unluckysample

<hr>

# Unlucky NTT sampling vector

The SampleNTT algorithm reads a variable number of bytes from an Extendable
Output Function to perform rejection sampling. The files in the unlucky/ folder
provide test vectors that cause many more rejections than usual.

In particular, these vectors require reading more than 575 bytes from the
SHAKE-128 XOF in SampleNTT, which would ordinarily happen with probability 2⁻³⁸.

Note that these vectors can be run through a regular deterministic ML-KEM
testing API (i.e. one that injects the d, z, m random values) since they were
bruteforced at the level of the d value.

If for some reason an implementation needs to draw a fixed amount of bytes from
the XOF, at least 704 bytes are necessary for a negligible probability (~ 2⁻¹²⁸)
of failure.
