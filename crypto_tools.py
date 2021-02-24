#!/usr/bin/env python3

from M2Crypto import EVP
from binascii import hexlify, unhexlify
import sys
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT


def m2_encrypt(plaintext, key, iv, key_as_bytes=False, padding=True):
   print("key")
   print(key)
   cipher = EVP.Cipher(alg="aes_128_ecb", key=key, iv=iv,
                       key_as_bytes=key_as_bytes, padding=padding, op=1)
   cipher.update(plaintext)

   cipher.final()


if __name__ == "__main__":
   print("AES encrypt and ")

   #if len(sys.argv) != 3:
   #    print("you need input like this:")
   #    print("./m2crypto_aes.py key_string data_string")
   #    exit()

   enc = 1
   dec = 0
   algs = ['aes', 'des', '3des2key', '3des3key', 'sm4', '0', '1', '2', '3', '4']
   # try:
   if True:
      while True:
         print("\n------------ start [<Q/q> Quit]--------------------")
         alg = input("algorithm [aes : 0, des : 1, 3des2key : 2, 3des3key: 3, sm4 : 4]: ")
         if alg == '':
            alg = 'aes'
         elif alg == 'q' or alg == 'Q':
            exit()
         elif alg not in algs:
            print("algorithm invalid, please input one of [aes des 3des sm4]")
            continue
         key = input("key    : ")
         data = input("data   : ")
         if alg == 'aes' or alg == '0':
            alg = 'aes_128_ecb'
            if len(key) != 32:
               print('aes key length is 16, please input right key.')
               continue
         elif alg == 'des' or alg == '1':
            # alg = 'des_ede_ecb'
            alg = 'des_ecb'
            if len(key) != 16:
               print('aes key length is 8, please input right key.')
               continue
         elif alg == '3des2key' or alg == '2':
            alg = 'des_ede_ecb'
            if len(key) != 32:
               print('aes key length is 16, please input right key.')
               continue
         elif alg == '3des3key' or alg == '3':
            alg = 'des_ede3_ecb'
            if len(key) != 48:
               print('aes key length is 24, please input right key.')
               continue
         elif alg == 'sm4' or alg == '4':
            if len(key) != 32:
               print('sm4 key length is 16, please input right key.')
               continue
            crypt_sm4 = CryptSM4()
            crypt_sm4.set_key(unhexlify(key), SM4_ENCRYPT)
            out = bytes.hex(crypt_sm4.crypt_ecb(unhexlify(data)))
            print("cipher : " + str(out[:len(data)]))
            print("------------ end --------------------")
            continue
         # m2_encrypt(data, key, iv, False, False)
         cipher = EVP.Cipher(alg=alg, key=unhexlify(key), iv=None, op=enc)
         # out = hexlify(cipher.update(unhexlify(data)))
         out = bytes.hex(cipher.update(unhexlify(data)))
         cipher.final()
         print("cipher : " + str(out))
         print("------------ end --------------------")
   #except:
      #exit()
