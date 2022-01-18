from BitVector import *
from time import time

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
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]





generated_s_box = [0] * 256

def generate_s_box():
    AES_modulus = BitVector(bitstring='100011011')

    for i in range(256):
        if i == 0:
            generated_s_box[i] = 0x63
        else:
            hex_now = hex(i)
            hex_to_send = hex_now[2 :]
            bv = BitVector(hexstring=hex_to_send)
            bv63 = BitVector(hexstring="63")
            bv_operational = bv.gf_MI(AES_modulus, 8)

            s = bv63 ^ bv_operational ^ (bv_operational << 1) ^ (bv_operational << 1) ^ (bv_operational << 1) ^ (bv_operational << 1)

            generated_s_box[i] = int(s)

generate_s_box()

def print_s_box():
    print("SBox : ")
    k = 1
    for i in range(256):
        print(hex(generated_s_box[i]) , end = " ")
        if k == 16:
            k = 0
            print()
        k = k + 1
    print()
    print()


print_s_box()
#print(generated_s_box)

generated_inverse_s_box = [0] * 256

def generate_inverse_s_box():
    AES_modulus = BitVector(bitstring='100011011')

    for i in range(256):
        if i == 99:
            generated_inverse_s_box[i] = 0x00
        else:
            #hex_now = hex(i)
            #hex_to_send = hex_now[2 :]
            #s = BitVector(hexstring=hex_to_send)
            s = BitVector(intVal=i , size=8)
            bv5 = BitVector(hexstring="05")

            bv = bv5 ^ (s << 1) ^ (s << 2) ^ (s << 3)

            bv_operational = bv.gf_MI(AES_modulus , 8)

            generated_inverse_s_box[i] = int(bv_operational.get_bitvector_in_hex() , base = 16)

generate_inverse_s_box()

def print_inverse_s_box():
    print("Inverse Sbox : ")
    k = 1
    for i in range(256):
        print(hex(generated_inverse_s_box[i]) , end = " ")
        if k == 16:
            k = 0
            print()
        k = k + 1
    print()
    print()


print_inverse_s_box()


def print_matrix(given):
    for i in range(4):
        #print()
        for j in range(4):
            print(given[i][j] , end = ' ')
        print()
    print()

def print_matrix_2(given):
    for i in range(4):
        #print()
        for j in range(44):
            print(given[i][j] , end = ' ')
        print()
    print()
    print()

    tracker = 16
    counter = 0
    for i in range(44):
        if tracker == 16:
            tracker = 0
            print()
            print("Round " , end = " ")
            print(counter , end = " ")
            print(" : " , end = " ")
            counter = counter + 1
        for j in range(4):
            print(given[j][i] , end = " ")
            tracker = tracker + 1

    print()
    print()

def matrix_maker(given):
    matrix = [[0] * 4 for i in range(4)]
    #print(matrix)
    k = 0
    for i in range(4):
        for j in range(4):
            take_one = given[k]
            that_one_in_hex = hex(ord(take_one))
            the_one_in_matrix = that_one_in_hex[2 : ]
            matrix[j][i] = BitVector(hexstring=the_one_in_matrix).get_bitvector_in_hex()
            k = k + 1

    return matrix


#key = input("Enter Key : ")
key = "Thats my Kung Fu"
key_size = len(key);
if key_size < 16:
    to_append = 16 - key_size
    for i in range(to_append):
        key = key + "0"
elif key_size > 16:
    part_to_take = ""
    for i in range(16):
        part_to_take = part_to_take + key[i]
    key = part_to_take

print(key)

key_matrix = matrix_maker(key)

print_matrix(key_matrix)

w_matrix = [[0] * 44 for i in range(4)]

#print_matrix_2(w_matrix)

for i in range(4):
    for j in range(4):
        w_matrix[i][j] = key_matrix[i][j]

#print_matrix_2(w_matrix)

def get_round_constant(just_check):
    round_constant_first_item = ["01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"]
    first_one = round_constant_first_item[int(just_check/4) - 1]
    to_be_returned = [first_one , "00" , "00" , "00"]
    return to_be_returned

def round_key_maker(start_column):
    w_previous_column = [0] * 4
    w_previous_column_left_shifted = [0] * 4
    w_byte_substituted = [0] * 4
    g_of_w_previous_column = [0] * 4

    for i in range(4):
        w_previous_column[i] = w_matrix[i][start_column - 1]

    for i in range(3):
        w_previous_column_left_shifted[i] = w_previous_column[i+1]
    w_previous_column_left_shifted[3] = w_previous_column[0]

    for i in range(4):
        b = BitVector(hexstring=w_previous_column_left_shifted[i])
        int_val = b.intValue()
        #s = Sbox[int_val]
        s = generated_s_box[int_val]
        s = BitVector(intVal=s, size=8)
        w_byte_substituted[i] = s.get_bitvector_in_hex()

    #round_constant = ["01" , "00" , "00" , "00"]
    round_constant = get_round_constant(start_column)

    for i in range(4):
        bv1 = BitVector(hexstring=w_byte_substituted[i])
        bv2 = BitVector(hexstring=round_constant[i])
        bv3 = bv1 ^ bv2
        g_of_w_previous_column[i] = bv3.get_bitvector_in_hex()

    for i in range(4):
        bv1 = BitVector(hexstring=w_matrix[i][start_column - 4])
        bv2 = BitVector(hexstring=g_of_w_previous_column[i])
        bv3 = bv1 ^ bv2
        w_matrix[i][start_column] = bv3.get_bitvector_in_hex()

    k = 3
    for i in range(3):
        for j in range(4):
            bv1 = BitVector(hexstring=w_matrix[j][start_column + i])
            bv2 = BitVector(hexstring=w_matrix[j][start_column - k])
            bv3 = bv1 ^ bv2
            w_matrix[j][start_column + (i+1)] = bv3.get_bitvector_in_hex()
        k = k - 1
    #print(w_previous_column)
    #print(w_previous_column_left_shifted)
    #print(w_byte_substituted)
    #print(g_of_w_previous_column)
    #print(type(w_previous_column[0]))

#round_key_maker(4)
key_scheduling_time = 0

start = time()
for i in range(10):
    round_key_maker((i+1) * 4)
#print(type(key_matrix[1][2]))
end = time()
key_scheduling_time = end - start
print("Key Scheduling Time : " , end = " ")
print(key_scheduling_time)
print()
print_matrix_2(w_matrix)






# plaintext = "Two One Nine Two"
# plaintext_size = len(plaintext);
# if plaintext_size < 16:
#     to_append = 16 - plaintext_size
#     for i in range(to_append):
#         plaintext = "0" + plaintext
#
# print(plaintext)
#
# plaintext_matrix = matrix_maker(plaintext)
# state_matrix = matrix_maker(plaintext)

#print_matrix(plaintext_matrix)

#state_matrix = [[0] * 4 for i in range(4)]

def add_round_key(state_matrix , w_position):
    for i in range(4):
        for j in range(4):
            bv1 = BitVector(hexstring=state_matrix[i][j])
            bv2 = BitVector(hexstring=w_matrix[i][j + w_position])
            bv3 = bv1 ^ bv2
            state_matrix[i][j] = bv3.get_bitvector_in_hex()

def substitute_bytes(state_matrix):
    for i in range(4):
        for j in range(4):
            b = BitVector(hexstring=state_matrix[i][j])
            int_val = b.intValue()
            #s = Sbox[int_val]
            s = generated_s_box[int_val]
            s = BitVector(intVal=s, size=8)
            state_matrix[i][j] = s.get_bitvector_in_hex()

def shift_row(state_matrix):
    temp_matrix = [[0] * 4 for i in range(4)]
    for i in range(4):
        for j in range(4):
            temp_matrix[i][j] = state_matrix[i][j]

    for i in range(4):
        shift_offset = i
        for j in range(4):
            state_matrix[i][j] = temp_matrix[i][(j + shift_offset) % 4]

def galois_field_multiplication(from_mixer , from_state_matrix):
    AES_modulus = BitVector(bitstring='100011011')

    bv1 = from_mixer
    bv2 = BitVector(hexstring=from_state_matrix)
    bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)

    return bv3

def mix_columns(state_matrix):
    temp_matrix = [[0] * 4 for i in range(4)]
    for i in range(4):
        for j in range(4):
            temp_matrix[i][j] = state_matrix[i][j]

    for i in range(4):
        for j in range(4):
            bv0 = galois_field_multiplication(Mixer[i][0] , temp_matrix[0][j])
            bv1 = galois_field_multiplication(Mixer[i][1] , temp_matrix[1][j])
            bv2 = galois_field_multiplication(Mixer[i][2] , temp_matrix[2][j])
            bv3 = galois_field_multiplication(Mixer[i][3] , temp_matrix[3][j])

            bv4 = bv0 ^ bv1 ^ bv2 ^ bv3
            state_matrix[i][j] = bv4.get_bitvector_in_hex()

def encryption(state_matrix):
    add_round_key(state_matrix , 0)

    for i in range(9):
        substitute_bytes(state_matrix)
        shift_row(state_matrix)
        mix_columns(state_matrix)
        add_round_key(state_matrix , (i+1) * 4)

    substitute_bytes(state_matrix)
    shift_row(state_matrix)
    add_round_key(state_matrix , 40)

# add_round_key(0)
# substitute_bytes()
# shift_row()
# mix_columns()
#encryption()

#print_matrix(state_matrix)






def inverse_substitute_bytes(state_matrix):
    for i in range(4):
        for j in range(4):
            b = BitVector(hexstring=state_matrix[i][j])
            int_val = b.intValue()
            #s = InvSbox[int_val]
            s = generated_inverse_s_box[int_val]
            s = BitVector(intVal=s, size=8)
            state_matrix[i][j] = s.get_bitvector_in_hex()

def inverse_mix_columns(state_matrix):
    temp_matrix = [[0] * 4 for i in range(4)]
    for i in range(4):
        for j in range(4):
            temp_matrix[i][j] = state_matrix[i][j]

    for i in range(4):
        for j in range(4):
            bv0 = galois_field_multiplication(InvMixer[i][0] , temp_matrix[0][j])
            bv1 = galois_field_multiplication(InvMixer[i][1] , temp_matrix[1][j])
            bv2 = galois_field_multiplication(InvMixer[i][2] , temp_matrix[2][j])
            bv3 = galois_field_multiplication(InvMixer[i][3] , temp_matrix[3][j])

            bv4 = bv0 ^ bv1 ^ bv2 ^ bv3
            state_matrix[i][j] = bv4.get_bitvector_in_hex()

def inverse_shift_row(state_matrix):
    temp_matrix = [[0] * 4 for i in range(4)]
    for i in range(4):
        for j in range(4):
            temp_matrix[i][j] = state_matrix[i][j]

    for i in range(4):
        shift_offset = i
        for j in range(4):
            state_matrix[i][j] = temp_matrix[i][(j - shift_offset + 4) % 4]

def decryption(state_matrix):
    add_round_key(state_matrix , 40)

    for i in range(9):
        inverse_shift_row(state_matrix)
        inverse_substitute_bytes(state_matrix)
        add_round_key(state_matrix , (9 - i) * 4)
        inverse_mix_columns(state_matrix)

    inverse_shift_row(state_matrix)
    inverse_substitute_bytes(state_matrix)
    add_round_key(state_matrix , 0)

#decryption()

#print_matrix(state_matrix)




def text_maker(given):
    text = ""
    for i in range(4):
        for j in range(4):
            text = text + chr(int(BitVector(hexstring=given[j][i])))

    return text

def process():
    #plaintext = "Two Nine One Two"
    file = open("input.txt" , "r")
    plaintext = file.readline()
    plaintext_size = len(plaintext);

    after_mod = plaintext_size % 16
    if after_mod != 0:
        to_append = 16 - after_mod
        for i in range(to_append):
            plaintext = plaintext + " "
    # if plaintext_size < 16:
    #     to_append = 16 - plaintext_size
    #     for i in range(to_append):
    #         plaintext = "0" + plaintext

    encryption_time = 0
    decryption_time = 0

    print("PlainText : " , end = " ")
    print(plaintext)
    plaintext_size = len(plaintext);
    print(plaintext_size)

    iteration_number = int(plaintext_size / 16)
    tracker = 0

    ciphertext = ""
    retrieved_text = ""

    for i in range(iteration_number):
        current_text = ""
        for j in range(16):
            current_text = current_text + plaintext[j + tracker]
        tracker = tracker + 16
        state_matrix = matrix_maker(current_text)

        start = time()

        encryption(state_matrix)
        #print_matrix(state_matrix)

        end = time()
        to_add = end - start
        encryption_time = encryption_time + to_add

        ciphertext = ciphertext + text_maker(state_matrix)


    tracker = 0
    for i in range(iteration_number):
        current_text = ""
        for j in range(16):
            current_text = current_text + ciphertext[j + tracker]
        tracker = tracker + 16
        state_matrix = matrix_maker(current_text)

        start = time()

        decryption(state_matrix)
        #print_matrix(state_matrix)

        end = time()
        to_add = end - start
        decryption_time = decryption_time + to_add

        retrieved_text = retrieved_text + text_maker(state_matrix)
    #plaintext_matrix = matrix_maker(plaintext)
    #state_matrix = matrix_maker(plaintext)
    print("CipherText : " , end = " ")
    print(ciphertext)
    print("Retrieved Text : " , end = " ")
    print(retrieved_text)
    # encryption(state_matrix)
    # print_matrix(state_matrix)
    # decryption(state_matrix)
    # print_matrix(state_matrix)

    print("Encryprion Time : " , end = " ")
    print(encryption_time)
    print("Decryprion Time : " , end = " ")
    print(decryption_time)

#process()

def process2():
    filename = input("Enter File Name : ")
    extension = filename[-3:]

    with open(filename, 'rb') as file:
        the_bytes = file.read()
        bytes_list = list(the_bytes)

        arr_len = len(bytes_list);
        string_arr = [0] * arr_len
        hex_arr = [0] * arr_len
        again_bytes = [0] * arr_len
        retrieved_bytes = [0] * arr_len

        file_plaintext = ""

        for i in range(arr_len):
            #hex_arr[i] = hex(bytes_list[i])
            string_arr[i] = chr(bytes_list[i])
        for i in range(arr_len):
            again_bytes[i] = ord(string_arr[i])

        for i in range(arr_len):
            file_plaintext = file_plaintext + string_arr[i]

        plaintext_size = len(file_plaintext)

        after_mod = plaintext_size % 16
        to_append = 0
        if after_mod != 0:
            to_append = 16 - after_mod
            for i in range(to_append):
                file_plaintext = file_plaintext + " "

        plaintext_size = len(file_plaintext)

        encryption_time = 0
        decryption_time = 0

        iteration_number = int(plaintext_size / 16)
        tracker = 0

        ciphertext = ""
        retrieved_text = ""

        for i in range(iteration_number):
            current_text = ""
            for j in range(16):
                current_text = current_text + file_plaintext[j + tracker]
            tracker = tracker + 16
            state_matrix = matrix_maker(current_text)

            start = time()

            encryption(state_matrix)
            # print_matrix(state_matrix)

            end = time()
            to_add = end - start
            encryption_time = encryption_time + to_add

            ciphertext = ciphertext + text_maker(state_matrix)

        tracker = 0
        for i in range(iteration_number):
            current_text = ""
            for j in range(16):
                current_text = current_text + ciphertext[j + tracker]
            tracker = tracker + 16
            state_matrix = matrix_maker(current_text)

            start = time()

            decryption(state_matrix)
            # print_matrix(state_matrix)

            end = time()
            to_add = end - start
            decryption_time = decryption_time + to_add

            retrieved_text = retrieved_text + text_maker(state_matrix)

        # print(len(bytes_list))
        # print(string_arr)
        # print(again_bytes)

        retrieved_text = retrieved_text[: len(retrieved_text) - to_append]

        print(arr_len)
        print(len(retrieved_text))
        print(len(retrieved_bytes))
        for i in range(arr_len):
            retrieved_bytes[i] = ord(retrieved_text[i])

        print(bytes_list)
        print(retrieved_bytes)

        print(len(file_plaintext))
        print(len(retrieved_text))

        txt = bytearray(retrieved_bytes)

        with open('output.'+extension, 'wb') as f:
            f.write(txt)


process2()