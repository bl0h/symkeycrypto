# In this task, you will explore the differences in
# security attained by the ECB and CBC modes of encryption. Using the AES-128
# primitive provided by your cryptographic library, implement your own versions of
# ECB and CBC modes of encryption (do not use the built-in methods for modes of
# operation). Your program should take a (plaintext) file, generate a random key (and
# random IV, in the case of CBC), and write the encryption of the plaintext in a new
# file.

from Crypto.Cipher import AES
import secrets
import base64
import sys


def main():
    key = secrets.token_bytes(16)  # Generate 16 random bytes (i.e., 128 bits)
    # Convert the bytes to a hex string for display purposes
    print('Random generated key: ' + key.hex())

    with open(sys.argv[2], 'rb') as f:
        header = f.read(54)  # BMP header is 54 bytes long
        plaintext = f.read()

    chunks = split_text(plaintext)

    if (sys.argv[1] == 'ecb'):
        ciphertext_chunks = ecb(chunks, key)
    elif (sys.argv[1] == 'cbc'):
        ciphertext_chunks = cbc(chunks, key)

    with open(sys.argv[3], 'wb') as outF:
        outF.write(header)
        outF.write(ciphertext_chunks)


# splits this into 128 bit chunks and then pads 0's if isn't 128 bits (16 bytes) long
def split_text(text):
    chunks = []
    for i in range(0, len(text), 16):
        chunk = text[i:i+16]
        if len(chunk) < 16:
            chunk += (hex(16-len(chunk))[2:4] * (16 - len(chunk))).encode()
        chunks.append(chunk)
    return chunks


def ecb(chunks, key):
    cipher = AES.new(key, AES.MODE_ECB)
    # ciphertext_chunks = []
    ciphertext_chunks = bytearray()
    for chunk in chunks:
        ciphertext_chunk = cipher.encrypt(chunk)
        # ciphertext_chunks.append(ciphertext_chunk)
        ciphertext_chunks.extend(ciphertext_chunk)
    return ciphertext_chunks


def cbc(chunks, key, iv=None):
    if (iv == None):
        # Generate 16 random bytes (i.e., 128 bits)
        iv = secrets.token_bytes(16)
    # Convert the bytes to a hex string for display purposes
    print('Init vector: ' + key.hex())
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_chunks = bytearray()
    initial = 0
    for chunk in chunks:
        if initial == 0:
            # xor with IV
            iv_int = int.from_bytes(iv, byteorder='big')
            chunk_int = int.from_bytes(chunk, byteorder='big')
            result_int = iv_int ^ chunk_int
            chunk = result_int.to_bytes(16, byteorder='big')
            initial += 1
        elif initial > 0:
            # xor with the previous ciphertext
            c_int = int.from_bytes(ciphertext_chunk, byteorder='big')
            chunk_int = int.from_bytes(chunk, byteorder='big')
            result_int = c_int ^ chunk_int
            chunk = result_int.to_bytes(16, byteorder='big')

        ciphertext_chunk = cipher.encrypt(chunk)
        # ciphertext_chunks.append(ciphertext_chunk)
        ciphertext_chunks.extend(ciphertext_chunk)
    return ciphertext_chunks


main()
