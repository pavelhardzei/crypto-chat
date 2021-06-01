from resources import EXPANSION, SBOX, PERMUTATION_TABLE, PC1, PC2, round_shifts


def apply_PC1(pc1_table: list[int], keys_64bits: int) -> int:
    keys_56bits = 0
    for index in pc1_table:
        keys_56bits = (keys_56bits << 1) | ((keys_64bits >> index) & 0b1)
    return keys_56bits


def split_in_half(keys_56bits: int) -> tuple[int, int]:
    left_keys, right_keys = keys_56bits >> 28, keys_56bits & 0xfffffff
    return left_keys, right_keys


def circular_left_shift(bits: int, numberofbits: int) -> int:
    temp = 0
    for i in range(28 - numberofbits):
        temp = (temp << 1) | 0b1
    shiftedbits = ((bits & temp) << numberofbits) | (bits >> temp)
    return shiftedbits


def apply_PC2(pc2_table: list[int], keys_56bits: int) -> int:
    keys_48bits = 0
    for index in pc2_table:
        keys_48bits = (keys_48bits << 1) | ((keys_56bits >> index) & 0b1)
    return keys_48bits


def generate_keys(key_64bits: int, round_shift: list[int]) -> list[int]:
    round_keys = []
    pc1_out = apply_PC1(PC1, key_64bits)
    L0, R0 = split_in_half(pc1_out)
    for roundnumber in range(16):
        newL = circular_left_shift(L0, round_shift[roundnumber])
        newR = circular_left_shift(R0, round_shift[roundnumber])
        roundkey = apply_PC2(PC2, (newL << 28) | newR)
        round_keys.append(roundkey)
        L0 = newL
        R0 = newR
    return round_keys


# des
def extension(encrypting_message: int, extension_table: list[int]) -> int:
    extended_message = 0
    for index in extension_table:
        extended_message = (extended_message << 1) | ((encrypting_message >> (31 - index)) & 0b1)
    return extended_message


def split_in_6bits(encryption_message: int) -> list[int]:
    return [(encryption_message >> (i * 6)) & 0b111111 for i in range(7, -1, -1)]


def get_first_and_last_bit(bits6: int) -> int:
    return (((bits6 >> 5) & 0b1) << 1) | (bits6 & 0b1)


def get_middle_four_bit(bits6: int) -> int:
    return (bits6 >> 1) & 0b1111


def sbox_lookup(sbox_number: int, first_last: int, middle4: int) -> int:
    return SBOX[sbox_number][first_last][middle4]


def permutation(encryption_message: int, permutation_table) -> int:
    cipher_text = 0
    for index in permutation_table:
        cipher_text = (cipher_text << 1) | (encryption_message >> (31 - index)) & 0b1
    return cipher_text


def round_function(encrypting_message: int, key: int) -> int:
    result = 0
    encrypting_message = extension(encrypting_message, EXPANSION)
    encrypting_message = encrypting_message ^ key
    bits6list = split_in_6bits(encrypting_message)
    for index, bits6 in enumerate(bits6list):
        first_last = get_first_and_last_bit(bits6)
        middle4 = get_middle_four_bit(bits6)
        result = (result << 4) | sbox_lookup(index, first_last, middle4)
    return permutation(result, PERMUTATION_TABLE)


def encrypt(encrypting_block: int, sub_keys: list[int]) -> int:
    left_part = encrypting_block >> 32
    right_part = encrypting_block & 0xffffffff

    for i in range(16):
        temp = right_part
        right_part = left_part ^ round_function(right_part, sub_keys[i])
        left_part = temp

    left_part, right_part = right_part, left_part

    return (left_part << 32) | right_part


def des(plain_text: list[bytes], flag: bool = False) -> list[bytes]:
    while len(plain_text[-1]) != 8:
        plain_text[-1] += b'0'

    key = b'gooddays'
    sub_keys = generate_keys(int.from_bytes(key, 'big'), round_shifts)
    if flag:
        sub_keys = sub_keys[::-1]

    result: list[bytes] = []
    for block in plain_text:
        block = int.from_bytes(block, 'big')
        result.append(encrypt(block, sub_keys).to_bytes(8, 'big'))
    return result


def hash_des(message: bytes):
    plain_text: list[bytes] = []
    if len(message) % 8 != 0:
        size = len(message) // 8 + 1
    else:
        size = len(message) // 8
    for i in range(size):
        plain_text.append(message[i * 8:(i + 1)*8])
    print(plain_text)
    return b''.join(des(plain_text))


def main():
    encrypted = des([b'helltome', b'123456'])
    print("Encrypting message: {}".format([b'helltome', b'123456']))
    print("After encrypting: {}".format(encrypted))

    decrypted = des(encrypted, True)

    print("Decrypting: {}".format(decrypted))


if __name__ == "__main__":
    main()
    print(hash_des(b'helltome123456'))