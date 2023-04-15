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

def main():
    key = secrets.token_bytes(16)  # Generate 16 random bytes (i.e., 128 bits)
    print(key.hex())  # Convert the bytes to a hex string for display purposes

    f = open('sample.txt', 'r')
    outF = open('output.txt', 'w')
    plaintext = f.read()
    chunks = split_text(plaintext)
    print(plaintext)
    cipher = AES.new(key, AES.MODE_ECB) 
    for chunk in chunks:
        chunk_bytes = chunk.encode('utf-8')
        ciphertext = cipher.encrypt(chunk_bytes)
        print(ciphertext)
        outF.write(base64.b64encode(ciphertext).decode('utf-8'));

    f.close()


def split_text(text):
    chunks = []
    for i in range(0, len(text), 16):
        chunk = text[i:i+16]
        # If the last chunk is less than 16 bytes, pad it with spaces
        if len(chunk) < 16:
            chunk += '\x00' * (16 - len(chunk))
        chunks.append(chunk)
    return chunks

main()