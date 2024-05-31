import streamlit as st
import struct

# SHA-224 constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Rotate right: rotates x right by n bits
def rotr(x, n):
    return (x >> n) | (x << (32 - n)) & 0xffffffff

# SHA-180 padding
def pad_message(message):
    original_length = len(message)
    message += b'\x80'
    message += b'\x00' * ((56 - (original_length + 1) % 64) % 64)
    message += struct.pack('>Q', original_length * 8)
    return message

# SHA-180 hash computation
def sha180(message):
    # Initial hash values for SHA-224
    H = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    ]

    # Pre-process the message
    message = pad_message(message)

    # Process the message in successive 512-bit chunks
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        W = list(struct.unpack('>16L', chunk)) + [0]*48

        for j in range(16, 64):
            s0 = rotr(W[j-15], 7) ^ rotr(W[j-15], 18) ^ (W[j-15] >> 3)
            s1 = rotr(W[j-2], 17) ^ rotr(W[j-2], 19) ^ (W[j-2] >> 10)
            W[j] = (W[j-16] + s0 + W[j-7] + s1) & 0xffffffff

        a, b, c, d, e, f, g, h = H

        for j in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[j] + W[j]) & 0xffffffff
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        H = [(x + y) & 0xffffffff for x, y in zip(H, [a, b, c, d, e, f, g, h])]

    # Produce the final hash value (big-endian)
    return ''.join(f'{value:08x}' for value in H[:6]) #45 chars

def extract_numbers(data):
    all_numbers=[]
    numbers = []
    hash_value = sha180(data.encode('utf-8'))
    looplimit = 100
    while len(all_numbers) != 5 : # 5 set of lotto numbers
        while len(numbers) != 6 :
            looplimit -= 1
            for i in range(0, len(hash_value), 8):
                num = int(hash_value[i:i+8], 16)
                num = (num % 45) + 1  # Convert to a number between 1 and 45
                if num not in numbers:
                    numbers.append(num)
            if len(numbers) != 6:
                numbers = []
                hash_value = sha180(hash_value.encode('utf-8'))
            if looplimit < 0 :
                print("Limit Loop count")
                break
        if sorted(numbers) not in all_numbers:
            all_numbers.append(sorted(numbers))
            numbers = []
            hash_value = sha180(hash_value.encode('utf-8'))
        if len(all_numbers) == 5 :
            break

    return sorted(all_numbers)

st.title('GOD LUCK 4 U :gift:')
st.subheader('입력한 데이터를 해싱하여 로또번호를 생성해드립니다.')
inputstring = st.text_area(label="원하는 문장, 단어, 숫자 및 특수문자 등 마음껏 입력하세요:",max_chars=1000,height=250)
numbers = extract_numbers(inputstring)
outputstring = ""
if len(inputstring) > 0 :
    temp = ""
    for number in numbers:
        temp += str(number) + "\n"
    outputstring = temp
st.text_area(label="생성된 로또 번호들:", value=outputstring, height=150)
