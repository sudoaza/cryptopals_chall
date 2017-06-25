#!/bin/env python2
from cpals import * 

cipher_text = load_b64f('6.txt')
probable_lens = get_xor_key_lens(cipher_text,6,40)
for key_len in probable_lens:
  key = brute_xor(cipher_text,key_len)
  clear = xor(cipher_text,key)
  if text_distance(clear) < 0.34:
    print text_distance(clear)
    print clear
    break

