import random


rng = random.SystemRandom()
EXP = 65537


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


class RSA():
    def __init__(self):
        pass

    def new_key(self, bits):
        bits //= 2
        z, e, p, q = EXP, EXP, 0, 0
        while not z % e:
            while p == q:
                p, q = (prime_generator(2 ** (bits - 1), 2 ** bits - 1)
                        for r in range(2))
            n = p * q
            z = (p - 1) * (q - 1)
        self.public = (e, n)
        self.private = (modinv(e, z), n)

    def encrypt(self, m):
        return pow(m, self.public[0], self.public[1])

    def decrypt(self, m):
        return pow(m, self.private[0], self.private[1])


if __name__ == '__main__':
    rsa = RSA()
    rsa.new_key(2048)
    m = rsa.encrypt(1234)
    print(m)
    m = rsa.decrypt(m)
    print(m)
