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
    print('Random generated key: ' + key.hex())  # Convert the bytes to a hex string for display purposes

    with open(sys.argv[1], 'rb') as f:
        header = f.read(54)  # BMP header is 54 bytes long
        plaintext = f.read()

    chunks = split_text(plaintext)
    
    cipher = AES.new(key, AES.MODE_ECB) 
    ciphertext_chunks = []
    for chunk in chunks:
        ciphertext_chunk = cipher.encrypt(chunk)
        ciphertext_chunks.append(ciphertext_chunk)

    with open(sys.argv[2], 'wb') as outF:
        outF.write(header);
        outF.write(b''.join(ciphertext_chunks))


#splits this into 128 bit chunks and then pads 0's if isn't 128 bits (16 bytes) long
def split_text(text):
    chunks = []
    for i in range(0, len(text), 16):
        chunk = text[i:i+16]
        if len(chunk) < 16:
            chunk += b'\x00' * (16 - len(chunk))
        chunks.append(chunk)
    return chunks

main()