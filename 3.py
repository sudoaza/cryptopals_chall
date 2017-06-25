#!/bin/env python2
from cpals import * 

cipher_text = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".decode('hex')
key = brute_byte_xor(cipher_text)
clear = xor(cipher_text,key)

print key
print text_distance(clear)
print clear
