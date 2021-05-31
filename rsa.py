import random


class RSA:

    @staticmethod
    def generate_keys(bit_length):
        p, q, n = RSA.__generate_pq(bit_length)
        phi = RSA.__euler_func(p, q)
        e = RSA.__generate_e(phi)
        d = RSA.__calculate_d(e, phi)
        open_key = (e, n)
        private_key = (d, n)
        return open_key, private_key

    @staticmethod
    def encrypt(m, open_key):
        return RSA.__binpow(m, open_key[0], open_key[1])

    @staticmethod
    def decrypt(c, private_key):
        return RSA.__binpow(c, private_key[0], private_key[1])

    @staticmethod
    def __generate_pq(bit_length):
        while True:
            number = RSA.__generate_big(bit_length)
            p = RSA.__miller_rabin(number)
            if p:
                p = number
                break
        while True:
            number = RSA.__generate_big(bit_length)
            q = RSA.__miller_rabin(number)
            if q:
                q = number
                break
        return p, q, p * q

    @staticmethod
    def __euler_func(p, q):
        return (p - 1) * (q - 1)

    @staticmethod
    def __generate_e(phi):
        while True:
            e = random.randint(3, phi - 1)
            if RSA.__gcd(e, phi) == 1:
                return e

    @staticmethod
    def __calculate_d(e, phi):
        d = RSA.__gcd_extended(e, phi)[1]
        if d < 0:
            d += phi
        return d

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

    @staticmethod
    def __test(d, p):
        a = random.randint(3, p - 2)
        x = RSA.__binpow(a, d, p)
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
            if not RSA.__test(d, p):
                return probability
        probability = 1 - 4**(-iterations)
        return probability


def test():
    keys = RSA.generate_keys(1024)
    plain_text = random.randint(1, keys[0][1] - 1)
    print("Plain text: {}".format(plain_text))
    cipher_text = RSA.encrypt(plain_text, keys[0])
    print("Encrypted: {}".format(cipher_text))
    decrypted = RSA.decrypt(cipher_text, keys[1])
    print("Encrypted: {}".format(decrypted))
    print(plain_text == decrypted)
    print(keys[0][0].bit_length(), keys[0][1].bit_length())


if __name__ == "__main__":
    test()