from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ciphertext

def decrypt(ciphertext, key):
    iv = ciphertext[:16]  
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

plaintext = input("Enter the plaintext to encrypt: ")  
key = get_random_bytes(16)  


ciphertext = encrypt(plaintext, key)
print("\nEncrypted Ciphertext (hex):", ciphertext.hex())


decrypted_text = decrypt(ciphertext, key)
print("\nDecrypted Text:", decrypted_text)
