from BitVector import *
import time

input_file = "input.txt"

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"),
     BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"),
     BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"),
     BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"),
     BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"),
     BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"),
     BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"),
     BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"),
     BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

Generated_SBox = [0] * 256

def create_SBox():
    AES_modulus = BitVector(bitstring='100011011')
    b63 = BitVector(hexstring="63")

    for i in range(256):
        if i == 0:
            Generated_SBox[i] = 0x63
            continue

        hexval = hex(i)
        hexval = hexval[2:]
        bv = BitVector(hexstring=hexval)

        bv = bv.gf_MI(AES_modulus, 8)

        s = b63 ^ bv ^ (bv<<1) ^ (bv<<1) ^ (bv<<1) ^ (bv<<1)
        Generated_SBox[i] = int(s.get_bitvector_in_hex(), base=16)



create_SBox()


Generated_Inv_SBox = [0] * 256

def create_Inv_SBox():
    for i in range(256):
        Generated_Inv_SBox[Generated_SBox[i]] = i


create_Inv_SBox()

round_constants = ["01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"]
round_keys = [["0"] * 16 for i in range(11)]
words = [["0"] * 44 for i in range(4)]
state = [["0"] * 4 for i in range(4)]

# key = input("Insert Key : ")
key = "Thats my Kung Fu"

# text = input("Insert your text: ")
text = "Two One Nine Two"



def make_matrix(string):
    # size = len(string)
    #
    # if size < 16:
    #     empty = 16 - size
    #     for i in range(empty):
    #         string = string + " "

    matrix = [[""] * 4 for _ in range(4)]
    k = 0
    for i in range(4):
        for j in range(4):
            temp = hex(ord(string[k]))
            temp = temp[2:4]
            matrix[j][i] = BitVector(hexstring=temp).get_bitvector_in_hex()
            k += 1

    return matrix


def print_matrix(given):
    size = len(given)
    for i in range(size):
        size2 = len(given[i])
        for j in range(size2):
            print(given[i][j], end=' ')

        print()


# def print_round_keys():


def add_padding(string):
    size = len(string)

    if size < 16:
        empty = 16 - size
        for i in range(empty):
            string = "0" + string

    return string


key_matrix = make_matrix(key)


# print_matrix(key_matrix)

# initialize w0 - w3


def g(w, rc):
    temp = w[0]
    for i in range(3):
        w[i] = w[i + 1]

    w[3] = temp

    for i in range(4):
        bit = BitVector(hexstring=w[i])
        val = bit.int_val()
        # x = Sbox[val]
        x = Generated_SBox[val]
        x = BitVector(intVal=x, size=8)
        w[i] = x.get_bitvector_in_hex()

    rc_matrix = [rc, "00", "00", "00"]

    for i in range(4):
        w[i] = (BitVector(hexstring=w[i]) ^ BitVector(hexstring=rc_matrix[i])).get_bitvector_in_hex()

    return w


def make_round_key(round):
    start_column = 4 * round

    words_prev_coulmn = ["0"] * 4
    for i in range(4):
        words_prev_coulmn[i] = words[i][start_column - 1]

    words_prev_coulmn = g(words_prev_coulmn, round_constants[round - 1])

    for i in range(4):
        bv1 = BitVector(hexstring=words[i][start_column - 4])
        bv2 = BitVector(hexstring=words_prev_coulmn[i])

        words[i][start_column] = (bv1 ^ bv2).get_bitvector_in_hex()

    for i in range(4):
        j = 1
        while j < 4:
            words[i][start_column + j] = (BitVector(hexstring=words[i][start_column + j - 4]) ^
                                          BitVector(hexstring=words[i][start_column + j - 1])).get_bitvector_in_hex()
            j += 1

# print_matrix(words)

def make_round_keys():
    for i in range(4):
        for j in range(4):
            words[i][j] = key_matrix[i][j]

    for i in range(10):
        make_round_key(i + 1)

# print("Key Scheduling time: " + str(end - start))

def get_round_keys():
    k = 0
    t = -1
    for j in range(44):
        if k % 16 == 0:
            k = 0
            t += 1
            # print()

        for i in range(4):
            # print(words[i][j], end=' ')
            round_keys[t][k] = words[i][j]
            k += 1


start = time.time()

make_round_keys()

end = time.time()
key_schedluing_time = end - start
get_round_keys()


def substitute_bytes():
    for i in range(4):
        for j in range(4):
            bits = BitVector(hexstring=state[i][j])
            val = bits.int_val()
            # x = Sbox[val]
            x = Generated_SBox[val]
            x = BitVector(intVal=x, size=8)
            state[i][j] = x.get_bitvector_in_hex()


def shift_rows_left():
    temp = [[""] * 4 for i in range(4)]

    for i in range(4):
        for j in range(4):
            temp[i][j] = state[i][j]

    for i in range(4):
        for j in range(4):
            state[i][j] = temp[i][(i + j) % 4]


def multiply(bv1, bv2):
    AES_modulus = BitVector(bitstring='100011011')

    return bv1.gf_multiply_modular(bv2, AES_modulus, 8)


def mix_columns():
    temp = [["0"] * 4 for i in range(4)]

    for i in range(4):
        for j in range(4):
            temp[i][j] = state[i][j]

    for i in range(4):
        for j in range(4):
            bv = BitVector(hexstring="00")
            for k in range(4):
                bv = bv ^ multiply(Mixer[i][k], BitVector(hexstring=temp[k][j]))

            state[i][j] = bv.get_bitvector_in_hex()


def add_round_key(round_no):
    k = 0
    # print("round : " + str(round_no))
    for i in range(4):
        for j in range(4):
            bv1 = BitVector(hexstring=state[j][i])
            bv2 = BitVector(hexstring=round_keys[round_no][k])
            # if k%4 == 0:
            #     print()
            # print(round_keys[round_no][k], end=' ')
            bv = bv1 ^ bv2
            state[j][i] = bv.get_bitvector_in_hex()
            k += 1

    # print()


def encrypt(text):
    temp = make_matrix(text)

    # print("Text in hex: ", end=' ')
    # for i in range(4):
    #     for j in range(4):
    #         print(temp[i][j], end='')
    #
    # print()

    for i in range(4):
        for j in range(4):
            state[i][j] = temp[i][j]

    add_round_key(0)
    # print()
    # print_matrix(state)

    for i in range(10):
        substitute_bytes()
        shift_rows_left()

        if i != 9:
            mix_columns()

        add_round_key(i + 1)


def shift_rows_right():
    temp = [[""] * 4 for i in range(4)]

    for i in range(4):
        for j in range(4):
            temp[i][j] = state[i][j]

    for i in range(4):
        for j in range(4):
            state[i][j] = temp[i][(j - i) % 4]


def inv_sub_bytes():
    for i in range(4):
        for j in range(4):
            bits = BitVector(hexstring=state[i][j])
            val = bits.int_val()
            # x = InvSbox[val]
            x = Generated_Inv_SBox[val]
            x = BitVector(intVal=x, size=8)
            state[i][j] = x.get_bitvector_in_hex()


def inv_mix_columns():
    temp = [["0"] * 4 for i in range(4)]

    for i in range(4):
        for j in range(4):
            temp[i][j] = state[i][j]

    for i in range(4):
        for j in range(4):
            bv = BitVector(hexstring="00")
            for k in range(4):
                bv ^= multiply(InvMixer[i][k], BitVector(hexstring=temp[k][j]))

            state[i][j] = bv.get_bitvector_in_hex()


def decrypt(cipher):
    for i in range(4):
        for j in range(4):
            state[i][j] = cipher[i][j]

    add_round_key(10)

    for i in range(10):
        shift_rows_right()
        inv_sub_bytes()
        add_round_key(9 - i)

        if i != 9:
            inv_mix_columns()



def text_file_process():
    file = open("input.txt", "r")
    ciphers = []
    encryption_time = 0
    while True:
        text = file.read(16)
        if not text:
            break
        print("text = " + text)
        start = time.time()
        encrypt(text)
        end = time.time()
        encryption_time += (end - start)

        temp = [["0"] * 4 for x in range(4)]

        for i in range(4):
            for j in range(4):
                temp[i][j] = state[i][j]

        ciphers.append(temp)


    print("Key in hex: ", end=' ')
    for i in range(16):
        print(round_keys[0][i], end='')


    print("Cipher text: ", end=' ')
    for ciph in ciphers:
        for i in range(4):
            for j in range(4):
                print(chr(int(BitVector(hexstring=ciph[j][i]))), end='')

    print()
    #
    decryption_time = 0

    results = []
    for c in ciphers:
        start = time.time()
        decrypt(c)
        end = time.time()
        decryption_time += (end - start)
        temp = [["0"] * 4 for x in range(4)]

        for i in range(4):
            for j in range(4):
                temp[i][j] = state[i][j]

        results.append(temp)



    # print_matrix(results)

    print("Deciphered text: ", end=' ')
    for ciph in results:
        for i in range(4):
            for j in range(4):
                print(chr(int(BitVector(hexstring=ciph[j][i]))), end='')

    print()

    print("Key Schedluin Time: " + str(key_schedluing_time))
    print("Encryption Time: " + str(encryption_time))
    print("Decryption Time: " + str(decryption_time))



# text_file_process()


def generic_process():
    filename = input_file
    ext = filename[-3:]

    with open(filename, 'rb') as file:
        bytes_read = file.read()
        bytes_list = list(bytes_read)

        size = len(bytes_list)
        string = [""] * size
        bytes_2 = [0] * size
        decrypted_bytes = [0] * size

        text = ""

        for i in range(size):
            string[i] = chr(bytes_list[i])
            bytes_2[i] = ord(string[i])
            text += string[i]


        text_size = len(text)

        rem = text_size % 16
        extra = 0
        if rem != 0:
            extra = 16 - rem

        for i in range(extra):
            text += " "

        text_size = len(text)
        encryption_time = 0

        count = int(text_size / 16)
        start_index = 0

        ciphers = []

        for i in range(count):
            current = ""

            for j in range(16):
                current = current + text[j + start_index]

            start_index += 16

            start = time.time()
            encrypt(current)
            end = time.time()

            encryption_time += (end - start)

            temp = [["0"] * 4 for x in range(4)]

            for j in range(4):
                for k in range(4):
                    temp[j][k] = state[j][k]

            ciphers.append(temp)


        result = ""
        decryption_time = 0

        for c in ciphers:
            start = time.time()
            decrypt(c)
            end = time.time()

            decryption_time += (end - start)

            for j in range(4):
                for k in range(4):
                    result += chr(int(BitVector(hexstring=state[k][j])))

        result = result[: len(result) - extra]


        for i in range(size):
            decrypted_bytes[i] = ord(result[i])

        bytes_to_write = bytearray(decrypted_bytes)

        with open('output.' + ext, 'wb') as f:
            f.write(bytes_to_write)

        print()
        size = len(round_keys)
        for i in range(size):
            print("Round key 0 : ", end=' ')
            for j in round_keys[i]:
                print(j, end = ' ')
            print()

        print()
        print("Key Schedluing Time: " + str(key_schedluing_time))
        print("Encryption Time: " + str(encryption_time))
        print("Decryption Time: " + str(decryption_time))



# text_file_process()

generic_process()


















