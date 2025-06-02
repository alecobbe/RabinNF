# Source-files
This is the code associated to the paper "The Rabin cryptosystem over number fields" by Alessandro Cobbe, Andreas Nickel, and Akay Schuster. 

System requirements: Pari 2.1 or higher. 

# Description: 
The following routines are provided: 

**1. Auxiliary function:**
- `sqroot`: computes the square root of a polynomial c mod p mod a fixed irreducible polynomial pol using a precomputed parameter bp representing a non-quadratic residue.

**2. Key generation:**
There are three different versions for the key generation algorithm, suitable for different choices of the irreducible polynomial pol, which has to be fixed once and for all. The primes of the private key might be chosen among possible congruences to elements of C (a vector) modulo D (an integer), or they might be chosen at random and discarded if they are not inert in the required number field. The parameter required by the sqroot function might or might not be computed, according to whether it is possible to compute square roots without the Tonelli-Shanks algorithm. All the different versions take a security parameter max which defines how big the prime numbers should be; it is 2^2048 by default. The output is a vector with the public key as its first component (an integer) and the secret key as its second component (a vector of two prime numbers and, in case, the precomputations for Tonelli-Shanks).
- `key_deg2`: this uses a list of congruences and does the precomputation for Tonelli-Shanks (to be used for quadratic fields, e.g. Gaussian integers: pol=x^2+1; C=[3]; D=8).
- `key_general`: this does not use a list of congruences and does the precomputation for Tonelli-Shanks (to be used for generic number fields, it requires only pol).
- `key_deg3`: this uses a list of congruences and does not the precomputation for Tonelli-Shanks (to be used for appropriate subextension of degree 3 of cyclotomic fields fields, e.g. pol=x^3+x^2-2*x-1; C=[3,11,19,23]; D=28).


**3. Encryption**
- `encrypt`: takes as input a message m and the public key pk, and returns a valid encryption consisting of the square of m modulo pk modulo pol and the two extra bits required to identify the correct message among the four possible square roots. The function is identical in all scenarios.


**4. Decryption**

- `decrypt_general`: takes as input the chiffre text and the secret key and returns the original message, in all cases requiring the Tonelli-Shanks algorithm, assuming that sk contains the precomputations (to be used for quadratic extensions and generic number fields).
- `decrypt_deg3`: takes as input the chiffre text and the secret key and returns the original message, when Tonelli-Shanks is not required (to be used for appropriate subextension of degree 3 of cyclotomic fields, e.g. pol=x^3+x^2-2*x-1).

**5. The classical Rabin cryptosystem**
We also included an implementation of the classical Rabin cryptosystem over Z to compare running times.
- `key_classic`: generates a public and a secret key of the classic Rabin cryptosystem; the prime numbers are taken to be congruent to 3 modulo 4.
- `encrypt_classic`:  takes as input a message m and the public key pk, and returns a valid encryption consisting of the square of m modulo pk and the two extra bits required to identify the correct message among the four possible square roots. 
- `decrypt_classic`: takes as input the chiffre text and the secret key and returns the original message, avoiding the use of the Tonelli-Shanks algorithm since primes are congruent to 3 modulo 4.

# Licence information: 

This code is shared under a **MIT License**, see 
<https://opensource.org/license/mit> 
