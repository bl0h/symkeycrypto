from operator import truediv
from pydoc import plain
from Crypto.Cipher import AES
import secrets
import base64
import sys
import encryption


key = secrets.token_bytes(16)
iv = secrets.token_bytes(16)


def submit(s):
    url = "userid=456;userdata=" + s + ";session-id=31337"
    encoded_url = ""
    for c in url:
        if (c == ";" or c == "="):
            encoded_url += "%" + hex(ord(c))[2:4]
        else:
            encoded_url += c
    url = pad(encoded_url)
    print(url)
    return encryption.cbc(encryption.split_text(bytes(url, "utf-8")), key, iv)


def verify(s):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = str(cipher.decrypt(s))
    print("verify plaintext: ", plaintext)
    if (plaintext.find(";admin=true;") > -1):
        return True
    return False


# pad with the remaining number of bytes value
def pad(s):
    pad_char = 16-len(s) % 16
    return s+chr(pad_char) * pad_char


def main():
    cipher = submit("You're the man now, dog")
    print(len(cipher))
    print("cipher: ", cipher)
    print("verify: ", verify(cipher))
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = aes.decrypt(cipher).decode()
    print("plaintext: ", plaintext)
    attack_str = ";admin=true;"
    # byte flipping
    for i in range(len(attack_str)):
        print("cipher val: ", cipher[i], " plain value: ",
              plaintext[i], " attack: ", attack_str[i])
        cipher[i] = (cipher[i] ^ ord(attack_str[i]) ^ ord(plaintext[i+16]))
        # this is normally 16 since that is our block size.
        # python puts an extra b" characters at the front of our string
        # in this concatenation, so we use 18 instead of 16 for the offsetting here
    print(verify(cipher))


main()
