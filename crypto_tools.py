#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from M2Crypto import EVP
from binascii import hexlify, unhexlify
import sys
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT


ENCRYPT = 1
DECRYPT = 0
algs = ['aes', 'des', '3des2key', '3des3key', 'sm4', '0', '1', '2', '3', '4']
modes = ['ecb', '0', 'cbc', '1']
ops = ['enc', '0', 'dec', '1']


def input_alg():
   alg = input("algorithm [aes: 0, des: 1, 3des2key: 2, 3des3key: 3, sm4: 4]: ")
   if alg == '':
      alg = 'aes'
   elif alg == 'q' or alg == 'Q':
      exit()
   elif alg not in algs:
      print("algorithm invalid, please input one of [aes des 3des sm4]")
      return None
   elif alg == '0':
      alg = 'aes'
   elif alg == '1':
      alg = 'des'
   elif alg == '2':
      alg = '3des2key'
   elif alg == '3':
      alg = '3des3key'
   elif alg == '4':
      alg = 'sm4'
   return alg

def input_op():
   op = input("encrypt or decrypt [enc: 0, dec: 1]: ")
   if op == 'q' or op == 'Q':
      exit()
   elif op == '':
      op = ENCRYPT
   elif op not in ops:
      print("encdec invalid, please input one of [enc dec]")
      return None
   elif op == 'enc' or op == '0':
      op = ENCRYPT
   elif op == 'dec' or op == '1':
      op = DECRYPT
   return op

def input_mode():
   mode = input("mode [ecb: 0, cbc: 1]: ")
   if mode == 'q' or mode == 'Q':
      exit()
   elif mode == '':
      mode = 'ecb'
   elif mode not in modes:
      print("mode invalid, please input one of [ecb cbc]")
      return None
   elif mode == '0':
      mode = 'ecb'
   elif mode == '1':
      mode = 'cbc'
   return mode

def input_key():
   key = input("key    : ")
   return key

def input_iv():
   iv = input("iv     : ")
   return iv

def input_iv(mode):
   if mode == 'ecb':
      iv = ''
   else:
      iv = input("iv     : ")
   return iv

def input_data():
   data = input("data   : ")
   return data

def get_alg_mode(alg, mode, key):
   if alg == 'aes':
      if mode == 'ecb':
         alg_mode = 'aes_128_ecb'
      elif mode == 'cbc':
         alg_mode = 'aes_128_cbc'
      if len(key) != 32:
         print('aes key length is 16, please input right key.')
         return None

   elif alg == 'des':
      if mode == 'ecb':
         alg_mode = 'des_ecb'
      elif mode == 'cbc':
         alg_mode = 'des_cbc'
      if len(key) != 16:
         print('aes key length is 8, please input right key.')
         return None

   elif alg == '3des2key':
      if mode == 'ecb':
         alg_mode = 'des_ede_ecb'
      elif mode == 'cbc':
         alg_mode = 'des_ede_cbc'
      if len(key) != 32:
         print('aes key length is 16, please input right key.')
         return None

   elif alg == '3des3key':
      if mode == 'ecb':
         alg_mode = 'des_ede3_ecb'
      elif mode == 'cbc':
         alg_mode = 'des_ede3_cbc'
      if len(key) != 48:
         print('aes key length is 24, please input right key.')
         return None

   return alg_mode

if __name__ == "__main__":
   print("Crypto tool for aes des sm4.")

   # try:
   if True:
      while True:
         print("\n------------ start [<Q/q> Quit]--------------------")
         alg = input_alg()
         if alg is None:
            continue

         op = input_op()
         if op is None:
            continue

         mode = input_mode()
         if mode is None:
            continue

         key = input_key()
         if key is None:
            continue

         iv = input_iv(mode)
         if iv is None:
            continue

         data = input_data()
         if data is None:
            continue

         if alg in ['aes', 'des', '3des2key', '3des3key']:
            alg_mode = get_alg_mode(alg, mode, key)
            if alg_mode == None:
               continue
            cipher = EVP.Cipher(alg=alg_mode, key=unhexlify(key), iv=unhexlify(iv), op=op, padding=False)
            out = bytes.hex(cipher.update(unhexlify(data)))
            cipher.final()
            print("cipher : " + str(out))

         elif alg == 'sm4':
            if len(key) != 32:
               print('sm4 key length is 16, please input right key.')
               continue
            crypt_sm4 = CryptSM4()
            if op == ENCRYPT:
               crypt_sm4.set_key(unhexlify(key), SM4_ENCRYPT)
            elif op == DECRYPT:
               crypt_sm4.set_key(unhexlify(key), SM4_DECRYPT)

            if mode == 'ecb':
               out = bytes.hex(crypt_sm4.crypt_ecb(unhexlify(data)))
            elif mode == 'cbc':
               out = bytes.hex(crypt_sm4.crypt_cbc(unhexlify(iv), unhexlify(data)))
            print("cipher : " + str(out[:len(data)]))

         print("------------ end ----------------")

   #except:
      #exit()
