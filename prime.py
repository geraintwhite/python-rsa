import math
import sys


def prime(n):
    if n % 2 == 0 or n % 3 == 0: return False

    for i in range(6, int(math.sqrt(n)), 6):
        if n % (i + 1) == 0 or n % (i - 1) == 0:
            return False

    return True


if __name__ == '__main__':
    for i in range(2, 64):
        n = 2**i - 1
        if prime(n): print(n)
    # print(prime(int(sys.argv[1])))
