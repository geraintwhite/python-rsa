import random
import math
import json
from base64 import b64encode, b64decode


rng = random.SystemRandom()
EXP, BS = 65537, 16


def is_prime(n, k=10):
    ''' uses the miller-rabin primality test for larger primes
        https://en.wikipedia.org/wiki/Miller-Rabin_primality_test '''

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41,
                    43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

    if n < 101:
        return n in small_primes
    elif any(n % i == 0 for i in small_primes):
        return False
    else:
        s, d = 0, n - 1
        while d & 1 == 0:
            s, d = s + 1, d >> 1
        for a in [rng.randint(2, n - 2) for r in range(k)]:
            x = pow(a, d, n)
            if x != 1 and x != n - 1:
                for r in range(s):
                    x = pow(x, 2, n)
                    if x == 1:
                        return False
                    elif x == a - 1:
                        a = 0
                        break
                if a:
                    return False
        return True


def prime_generator(lower, upper):
    ''' returns random prime number between upper and lower bounds '''

    n = 0
    while not is_prime(n):
        n = rng.randint(lower, upper)
        n += ~n & 1
    return n


def egcd(a, b):
    ''' returns tuple of three values: x, y, z
        such that x is the gcd of a and b, and x = ay + bz '''

    if not a:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def modinv(a, m):
    ''' returns the multiplicative inverse x of a modulo m
        such that a x = 1 (mod m) '''

    g, x, y = egcd(a, m)
    if g:
        return x % m
    else:
        return False


def bytes_to_int(bytes_):
    ''' returns an integer from a list of bytes '''

    value = 0
    for byte in bytes_:
        value = (value << 8) + byte
    return value


def int_to_bytes(value, min_len=0):
    ''' returns a list of bytes from an integer '''

    bytes_ = []
    while value > 0:
        bytes_.append(value & 255)
        value >>= 8

    while len(bytes_) < min_len:
        bytes_.append(0)

    bytes_.reverse()
    return bytes_


def int_to_b64(value):
    ''' returns base64 equivalent of an integer '''

    bytes_ = bytes(int_to_bytes(value))
    b64 = b64encode(bytes_).decode()
    return b64


def b64_to_int(b64):
    ''' returns integer equivalent of a base64 string '''

    bytes_ = b64decode(b64.encode())
    value = bytes_to_int(bytes_)
    return value


class RSA():
    def __init__(self):
        ''' initialise key values '''

        self.n, self.d, self.e = 0, 0, 0

    def new_key(self, bits=2048):
        ''' stores a new public and private key in the object '''

        bits //= 2
        z, e, p, q = EXP, EXP, 0, 0
        while not z % e:
            while p is q:
                p, q = (prime_generator(2 ** (bits - 1), 2 ** bits - 1)
                        for r in range(2))
            z = (p - 1) * (q - 1)
        n, d = p * q, modinv(e, z)
        self.n, self.e, self.d = n, e, d
        self.key_length = math.ceil(math.log(n, 256))

    def encrypt(self, data, bs=BS):
        ''' encrypt data with stored public key '''

        data, value = list(data), 0
        while len(data) % bs:
            data.append(0)

        out = []
        for x in range(0, len(data), bs):
            a = bytes_to_int(data[x:x + bs])
            b = pow(a, self.e, self.n)
            out.extend(int_to_bytes(b, self.key_length))

        return bytes(out)

    def decrypt(self, data, bs=BS):
        ''' decrypt data with stored private key '''

        data, out = list(data), []
        for x in range(0, len(data), self.key_length):
            a = bytes_to_int(data[x:x + self.key_length])
            b = pow(a, self.d, self.n)
            out.extend(int_to_bytes(b))

        return bytes(out)

    def import_key(self, key):
        ''' import key values from json string '''

        key = json.loads(key)

        self.n = b64_to_int(key['n']) if key['n'] else self.n
        self.e = b64_to_int(key['e']) if key['e'] else self.e
        self.d = b64_to_int(key['d']) if key['d'] else self.d

        self.key_length = math.ceil(math.log(self.n, 256))

    def export_key(self, private=False):
        ''' export key values to json string '''

        return json.dumps({
            'n': int_to_b64(self.n),
            'e': int_to_b64(self.e),
            'd': int_to_b64(self.d) if private else False
        })


if __name__ == '__main__':
    with open('rsa.py', 'rb') as f:
        data = f.read()

    rsa = RSA()
    rsa.new_key()

    key = rsa.export_key()

    print(key)

    rsa2 = RSA()
    rsa2.import_key(key)

    cipher = rsa2.encrypt(data)

    print(cipher)

    plaintext = rsa.decrypt(cipher).decode()

    print(plaintext)
