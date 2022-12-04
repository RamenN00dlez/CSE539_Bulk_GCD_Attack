#!/usr/bin/env python3

from math import gcd
from time import time
from sage.all import random_prime
import random
from datetime import datetime, timedelta

def RSA_Keygen(bits):
    try:
        p = random_prime(2**(bits // 2) - 1, False, 2**(bits // 2 - 1))
        q = random_prime(2**(bits // 2) - 1, False, 2**(bits // 2 - 1))
        n = p*q
        e = 65537
        d = pow(e, -1, (p-1)*(q-1))
        #print(f"{n.nbits()} - {bin(n)}")
        #print(f"p = {p}\nq = {q}\nn = {n}\ne = {e}\nd = {d}\n")
        return (n, e, d, p, q)
    except:
        return RSA_Keygen(bits)

def RSA_Key_Test(n, e, d):
    text = "w"
    text_int = 0
    for ch in text:
        text_int *= 2**8 
        text_int += ord(ch)
    ciphertext_int = pow(text_int, e, n)
    ciphertext = int(ciphertext_int).to_bytes((int(ciphertext_int).bit_length() + 7) // 8, "big")
    plaintext_int = pow(ciphertext_int, d, n)
    plaintext = int(plaintext_int).to_bytes((int(plaintext_int).bit_length() + 7) // 8, "big")
    assert (plaintext_int == text_int), "RSA Key Verification Failed."

def birthday(n, count):
    unique = 1
    for i in range(count):
        unique *= ((n - i) / n)
    return 1 - unique
def main():
    num_keys = int(input("Please enter the number of RSA keys to be generated\n> "))
    key_bits = int(input("Please enter the number of bits per RSA key\n> "))
    rsa_keys = []
    
    for _ in range(num_keys):
        (n, e, d, p, q) = RSA_Keygen(bits=key_bits)
        RSA_Key_Test(n, e, d)
        rsa_keys.append({"n": n, "e": e, "d": -1, "p": 1, "q": 1})

    time_start = datetime.now()

    for i, key1 in enumerate(rsa_keys[:-1]):
        for j, key2 in enumerate(rsa_keys[i + 1:]):
            shared_p = gcd(key1["n"], key2["n"])
            if (shared_p == 1):
                continue
            q1 = key1["n"] / shared_p
            q2 = key2["n"] / shared_p
            totient_n1 = int((shared_p - 1) * (q1 - 1))
            totient_n2 = int((shared_p - 1) * (q2 - 1))
            d1 = pow(key1["e"], -1, totient_n1)
            d2 = pow(key2["e"], -1, totient_n2)
            rsa_keys[i]["d"] = d1
            rsa_keys[i]["p"] = shared_p
            rsa_keys[i]["q"] = q1
            rsa_keys[j + i + 1]["d"] = d2
            rsa_keys[j + i + 1]["p"] = shared_p
            rsa_keys[j + i + 1]["q"] = q2
    rsa_broken_keys = [key for key in rsa_keys if key["d"] != -1]

    time_end = datetime.now()
    time_delta = time_end - time_start
    approx_n = (2**(key_bits // 2) - 1 - 2**(key_bits // 2 - 1)) // 50 # prime numbers must only end in 1, 3, 7, 9 (4/10 odds) and most are not prime (generously round down to 2/100 for 2 primes per 100 numbers)
    one_collision_probability = birthday(n=approx_n, count=num_keys * 2)
    
    for key in rsa_broken_keys:
        RSA_Key_Test(key["n"], key["e"], key["d"])
    print("Verified Broken RSA keys:", *rsa_broken_keys, sep=",\n")
    print(f"Probability of at least one collision is at least: {one_collision_probability}\nPerformed in {str(time_delta)}")

if (__name__ == "__main__"):
    main()
