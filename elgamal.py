import random
from hash_lib import hash_des


class ElGamal:

    @staticmethod
    def generate_keys(bit_length):
        p = ElGamal.__generate_p(bit_length)
        g = 2
        x = random.randint(2, p - 1)
        y = ElGamal.__binpow(g, x, p)
        open_key = (p, g, y)
        private_key = (p, g, x)
        return open_key, private_key

    @staticmethod
    def subscribe(message, private_key):
        hashed = int.from_bytes(hash_des(bytes(str(message), encoding='utf-8')), 'big')
        r = ElGamal.__generate_r(private_key[0])
        a = ElGamal.__binpow(private_key[1], r, private_key[0])
        inverse_r = ElGamal.__gcd_extended(r, private_key[0] - 1)[1]
        b = ((hashed - private_key[2] * a) * inverse_r) % (private_key[0] - 1)
        return a, b

    @staticmethod
    def verification(message, signature, open_key):
        hashed = int.from_bytes(hash_des(bytes(str(message), encoding='utf-8')), 'big')
        f1 = ElGamal.__binpow(open_key[1], hashed, open_key[0])
        f2 = (ElGamal.__binpow(open_key[2], signature[0], open_key[0]) *
              ElGamal.__binpow(signature[0], signature[1], open_key[0])) % open_key[0]
        return f1 == f2

    @staticmethod
    def __generate_p(bit_length):
        while True:
            number = ElGamal.__generate_big(bit_length)
            p = ElGamal.__miller_rabin(number)
            if p:
                p = number
                break
        return p

    @staticmethod
    def __generate_r(p):
        while True:
            r = random.randint(1, p - 1)
            if ElGamal.__gcd(r, p - 1) == 1:
                break
        return r

    @staticmethod
    def __generate_big(bit_length):
        return random.randint(2 ** (bit_length - 1), 2 ** bit_length - 1)

    @staticmethod
    def __binpow(a, n, m):
        a %= m
        res = 1
        while n > 0:
            if n & 0b1:
                res = (res * a) % m
            a = (a * a) % m
            n >>= 1
        return res

    @staticmethod
    def __test(d, p):
        a = random.randint(3, p - 2)
        x = ElGamal.__binpow(a, d, p)
        if x == 1 or x == p - 1:
            return True
        while d != p - 1:
            x = (x * x) % p
            d *= 2
            if x == 1:
                return False
            if x == p - 1:
                return True
        return False

    @staticmethod
    def __miller_rabin(p, iterations: int = 5):
        probability = 0
        if p == 1 or p % 2 == 0:
            return probability
        if p <= 3:
            return 1
        d = p - 1
        while d % 2 == 0:
            d //= 2
        for i in range(iterations):
            if not ElGamal.__test(d, p):
                return probability
        probability = 1 - 4 ** (-iterations)
        return probability

    @staticmethod
    def __gcd(a, n):
        if n > a:
            a, n = n, a
        while n != 0:
            a %= n
            a, n = n, a
        return a

    @staticmethod
    def __gcd_extended(a, b):
        x = 1
        y = 0
        x1 = 0
        y1 = 1
        a1 = a
        b1 = b
        while b1:
            q = a1 // b1
            x, x1 = x1, x - q * x1
            y, y1 = y1, y - q * y1
            a1, b1 = b1, a1 - q * b1
        return a1, x, y


def __gcd_extended(a, b):
    x = 1
    y = 0
    x1 = 0
    y1 = 1
    a1 = a
    b1 = b
    while b1:
        q = a1 // b1
        x, x1 = x1, x - q * x1
        y, y1 = y1, y - q * y1
        a1, b1 = b1, a1 - q * b1
    return a1, x, y


def test():
    keys = ElGamal.generate_keys(256)
    m = random.randint(0, keys[0][0] - 2)
    print(f"Message: {m}")
    signature = ElGamal.subscribe(m, keys[1])
    print(f"Signature: {signature}")
    print(f"Verification: {ElGamal.verification(m, signature, keys[0])}")


if __name__ == "__main__":
    test()