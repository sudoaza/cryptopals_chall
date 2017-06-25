#!/bin/env python2
from cpals import * 

with open('5.txt') as f:
    cipher_text = f.read().strip().decode("hex")
    key = brute_xor(cipher_text,3)
    clear = xor(cipher_text, key)
    print text_distance(clear)
    print clear

