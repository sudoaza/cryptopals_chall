#!/bin/env python2
from cpals import * 

f = open('4.txt','r')
for line in f.readlines():
  cipher_text = line.strip().decode('hex')
  key = brute_byte_xor(cipher_text)
  clear = xor(cipher_text,key)
  if text_distance(clear) < 0.35:
    print clear
    break
