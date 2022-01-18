# Task 1

import time
import sys
from BitVector import *

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

rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

AES_modulus = BitVector(bitstring='100011011')

padding = 0

block_s = 16
rcon_s = 10
n_rkey = 11

def init(key_bit_len):
    global block_s, rcon_s, n_rkey
    if key_bit_len == 128:
        block_s = 16
        rcon_s = 10
        n_rkey = 11
    elif key_bit_len == 192:
        block_s = 24
        rcon_s = 8
        n_rkey = 13
    elif key_bit_len == 256:
        block_s = 32
        rcon_s = 7
        n_rkey = 15


def key_input():
    key = input('Please input a key: ')
    # key = "Thats my Kung Fu"
    key_len = len(key)

    if key_len > 16:
        key_hex = [(ord(ch)) for ch in key[0:16]]
    elif key_len < 16:
        key_hex = [(ord(ch)) for ch in key[0:16]]
        n = 16 - key_len
        key_hex = key_hex + [0 for i in range(n)]
    else:
        key_hex = [(ord(ch)) for ch in key[0:16]]
    return key_hex

key_hex = key_input()
w = [[[key_hex[i*4+j] for j in range(4)] for i in range(4)]]

def print_matrix(mat, dim):
    if dim == 1:
        print([hex(v) for v in mat])
    elif dim == 2:
        for row in mat:
            print([hex(v) for v in row])
    elif dim == 3:
        for box in mat:
            print('[')
            for row in box:
                print('  ', [hex(v) for v in row])
            print(']')

def g(w, rc):
    w_cpy = w[:]
    w_cpy.append(w_cpy.pop(0)) # circular left shift
    wsub = [Sbox[b] for b in w_cpy] # substitution
    rc_vec = [rc, 0x00, 0x00, 0x00]
    return [BitVector(intVal=_ws, size=8) ^ BitVector(intVal=_rc, size=8) for _ws, _rc in zip(wsub, rc_vec) ]

def gen_rkey(round):
    prev_rkey = w[round-1]
    next_rkey = [[(BitVector(intVal=w0, size=8) ^ gw3).int_val() for w0, gw3 in zip(prev_rkey[0], g(prev_rkey[3], rcon[round-1]))]]
    for i in range(1, 4):
        next_rkey = next_rkey + [[(BitVector(intVal=wi, size=8) ^ BitVector(intVal=wii, size=8)).int_val() for wi, wii in zip(prev_rkey[i], next_rkey[i-1])]]
    
    # print([[hex(i) for i in k] for k in next_rkey])

    return next_rkey

def make_round_keys():
    global w
    for i in range(1, 11):
        w = w + [gen_rkey(i)]

def ascii_input(fname):
    global padding
    txt = ''
    if not fname:
        txt = input('Enter text: ')
        # txt = 'Two One Nine Two'
        txt_len = len(txt)

        if txt_len % 16 != 0:
            padding = 16 - (txt_len % 16)
            txt += "".join([' ' for i in range(padding)])
        return [[ord(c) for c in txt[block:block+16]] for block in range(0, txt_len, 16)]

    else:
        with open(fname, 'rb') as file:
            txt = file.read()
            b_lst = list(txt)
            if len(b_lst) % 16 != 0:
                padding = 16 - (len(b_lst) % 16)
                b_lst += [ord(' ') for i in range(padding)]
            return [[b for b in b_lst[block:block+16]] for block in range(0, len(b_lst), 16)] 


def add_round_key(state, round_no):
    trans_round_key = [list(t) for t in zip(*w[round_no])]

    # XOR corresponding entries
    return [[(BitVector(intVal=s, size=8) ^ BitVector(intVal=r, size=8)).int_val() for s, r in zip(s_row, trk_row)] 
        for s_row, trk_row in zip(state, trans_round_key)] 

def subbytes(state):
    return [[Sbox[i] for i in row] for row in state]

def inv_subbytes(state):
    return [[InvSbox[i] for i in row] for row in state]

def shift_row(state):
    return [state[0]] + [state[1][1:] + state[1][:1]] + [state[2][2:] + state[2][:2]] + [state[3][3:] + state[3][:3]]

def inv_shift_row(state):
    return [state[0]] + [state[1][-1:] + state[1][:-1]] + [state[2][-2:] + state[2][:-2]] + [state[3][-3:] + state[3][:-3]]

def list_xor(lst):
    res = 0
    for x in lst:
        res ^= x
    # print([hex(v) for v in lst], hex(res))
    return res

def mix_column(state):
    return [[list_xor([(m_bitvec.gf_multiply_modular(BitVector(intVal=s, size=8), AES_modulus, 8)).int_val() for m_bitvec, s in zip(m_row, s_col)])
        for s_col in zip(*state)] for m_row in Mixer]

def inv_mix_column(state):
    return [[list_xor([(m_bitvec.gf_multiply_modular(BitVector(intVal=s, size=8), AES_modulus, 8)).int_val() for m_bitvec, s in zip(m_row, s_col)])
        for s_col in zip(*state)] for m_row in InvMixer]

def encrypt(char_list):
    encrypted = []
    for block in char_list:
        state = [[v for v in block[row:row+4]] for row in range(0, 16, 4)] # build matrix from 1D list
        state = [list(t) for t in zip(*state)] # build column major matrix aka transpose
        cur_state = add_round_key(state, 0)

        for rkey in range(1, 10):
            cur_state = subbytes(cur_state)
            cur_state = shift_row(cur_state)
            cur_state = mix_column(cur_state)
            cur_state = add_round_key(cur_state, rkey)
            # print([[hex(v) for v in row] for row in cur_state])
        
        cur_state = subbytes(cur_state)
        cur_state = shift_row(cur_state)
        cur_state = add_round_key(cur_state, 10)
        # print([[hex(v) for v in row] for row in cur_state])

        enc_block = sum([list(t) for t in zip(*cur_state)], [])
        encrypted += [enc_block]
        # print([hex(v) for v in  trans_cur_state])
    return encrypted
    
def decrypt(enc_txt):
    txt = []
    for block in enc_txt:
        state = [[v for v in block[row:row+4]] for row in range(0, 16, 4)] # build matrix from 1D list
        state = [list(t) for t in zip(*state)] # build column major matrix aka transpose
        cur_state = add_round_key(state, 10)

        for rkey in range(9, 0, -1):
            cur_state = inv_shift_row(cur_state)
            cur_state = inv_subbytes(cur_state)
            cur_state = add_round_key(cur_state, rkey)
            cur_state = inv_mix_column(cur_state)

        cur_state = inv_shift_row(cur_state)
        cur_state = inv_subbytes(cur_state)
        cur_state = add_round_key(cur_state, 0)

        dec_block = sum([list(t) for t in zip(*cur_state)], [])
        txt += dec_block
    del txt[-padding:]
    return bytearray(txt)

def calc_sbox_entry(n):
    b = BitVector(intVal=n, size=8)
    b = b.gf_MI(AES_modulus, 8)
    return (BitVector(intVal=0x63, size=8) ^ b ^ (b << 1) ^ (b << 1) ^ (b << 1) ^ (b << 1)).int_val()

def calc_sbox():
    return [0x63] + [calc_sbox_entry(i) for i in range(1, 256)]

def calc_inv_sbox():
    inv_sbox = [0 for i in range(256)]
    for i in range(256):
        inv_sbox[Sbox[i]] = i
    return inv_sbox


t = time.process_time()
make_round_keys()
key_sched_t = time.process_time() - t

char_list = ascii_input(sys.argv[1])
ext = sys.argv[1][sys.argv[1].rfind('.'):]

t = time.process_time()
enc = encrypt(char_list)
enc_t = time.process_time() - t

t = time.process_time()
txt = decrypt(enc)
print(type(txt))
dec_t = time.process_time() - t

# print(txt.decode('utf-8'))
print('Key scheduling time:', key_sched_t)
print('Encryption time:', enc_t)
print('Decryption time:', dec_t)

with open('output'+ext, 'wb') as f:
    f.write(txt)

# print([[hex(v) for v in row] for row in enc])


from pprint import pprint
# arr = [[j for j in range(i*4, (i+1)*4)] for i in range(4)]
# pprint(arr)
# print([[hex(v) for v in block] for block in ascii_input()])

# hexw = [[[hex(val) for val in D] for D in DD] for DD in w]
# pprint(hexw)

# res = g(w[0][3], '01')

# print([r for r in res])
