import os
import sys
import random

def is_probable_prime(n, k=40):
    """Miller-Rabin primality test to check if n is prime."""
    if n < 2:
        return False
    # Check small primes
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    # Write n-1 as 2^s * d
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    rand = random.SystemRandom()
    for _ in range(k):
        a = rand.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generate a prime number of specified bit length."""
    rand = random.SystemRandom()
    while True:
        candidate = rand.getrandbits(bits)
        # Ensure candidate has the proper bit length and is odd.
        candidate |= (1 << (bits - 1)) | 1  
        if is_probable_prime(candidate):
            return candidate

def extended_gcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """Compute the modular inverse of a modulo m."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

def generate_rsa_keys(bits=512):
    """Generate RSA keys using two primes of the given bit length."""
    p = generate_prime(bits)
    q = generate_prime(bits)
    # Ensure p and q are distinct.
    while q == p:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if phi % e == 0:
        # In rare cases, choose different primes if e divides phi.
        return generate_rsa_keys(bits)
    d = modinv(e, phi)
    return (n, e, d)

def write_keys(username, n, e, d):
    pub_filename = f"{username}.pub"
    prv_filename = f"{username}.prv"
    with open(pub_filename, "w") as f:
        f.write(f"{n}\n{e}\n")
    with open(prv_filename, "w") as f:
        f.write(f"{n}\n{d}\n")
    print(f"RSA key pair for {username} generated successfully.")
    print(f"Public key saved in {pub_filename}")
    print(f"Private key saved in {prv_filename}")

def main():
    if len(sys.argv) != 2:
        print("Usage: ./genkeys.py <username>")
        sys.exit(1)
    username = sys.argv[1]
    # Generate two 512-bit primes (resulting in a 1024-bit modulus).
    n, e, d = generate_rsa_keys(bits=512)
    write_keys(username, n, e, d)

if __name__ == "__main__":
    main()
