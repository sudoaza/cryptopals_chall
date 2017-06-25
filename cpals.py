import math
from pwn import *
from itertools import cycle

def entropy(string):
  "Calculates the Shannon entropy of a string"
  # get probability of chars in string
  prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
  # calculate the entropy
  entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
  return entropy

def entropy_ideal(length):
  "Calculates the ideal Shannon entropy of a string with given length"
  prob = 1.0 / length
  return -1.0 * length * prob * math.log(prob) / math.log(2.0)

def text_distance(string):
  "Calculates the ocurrance of the most used letters in english. May work for other langs."
  # get ocurrance of chars in string
  ocurrance = [ float(string.count(c)) / float(len(string)) for c in ["e","t","a","o","i","n","s"," ","z","j"] ]
  
  # everything except lower case letters and space
  ocurrance.append( len( filter(lambda x: ((ord(x) < 97 or ord(x) > 117) and x != " "), string) ) / float(len(string)) )
  # weird symbols
  ocurrance.append( len( filter(lambda x: ((ord(x) < 65 and ord(x) not in [9,10,13]) or ord(x) > 126), string) ) / float(len(string)) )
  # weird but not so weird
  ocurrance.append( len( filter(lambda x: (ord(x) < 32 or ord(x) > 122), string) ) / float(len(string)) )
  # get the distance from the desired frequency
  expected = [0.13,0.9,0.8,0.75,0.73,0.7,0.62,0.2,0.01,0.01,0.11,0.08,0.01] 
  errors = [ (abs(ocurrance[i] - expected[i]) / expected[i]) ** 2 for i in range(len(expected)) ]
  #print ocurrance, errors
  return math.sqrt(sum(errors)) / len(expected)

# pwn tiene su propio xor
#def xor(string, key):
#  "Calculates the xor of the string with the key"
#  encrypted = [ chr(ord(a) ^ ord(b)) for (a,b) in zip(string, cycle(key)) ]
#  return "".join(encrypted)

def brute_byte_xor(string):
  "Bruteforces the 1 byte key of especified length for a xored string."
  best = 99999999
  key = "\x00"
  acceptable_distance = 0.35
  
  for i in range(2**8):
    plain = xor(string,chr(i))
    freq = text_distance(plain)
    if freq < best:
      best = freq
      key = chr(i)
      #print "new best guess ",key," ",best

  if best < acceptable_distance:
    print "key: ", key
    print "dist: ", best
    print "clear: ", xor(string,key)

  return key
    
def brute_xor(string, key_len):
  "Bruteforces the key of especified length for a xored string."
  blocks = [string[i:i + key_len] for i in xrange(0, len(string), key_len)]
  key = []
  for i in range(key_len):
    key.append( brute_byte_xor("".join([ item[i] if len(item) > i else "" for item in blocks])) )
  key = "".join(key)
  return key

def hamming(base,compare):
  "Calculares the hamming distance between two strings, depends on pwntools for xor & bits"
  return sum(bits(xor(base,compare)))

def get_xor_key_lens(string,min_len=2,max_len=16):
  sample_size = 8
  distances = []
  lengths = range(min_len,max_len+1)
  for l in lengths:
    dist = 0
    for i in range(sample_size):
      dist += hamming(string[i:i+l-1],string[i+l:i+2*l-1])
    dist = float(dist) / (sample_size * l)
    distances.append(dist)

  o_lens = [x for (y,x) in sorted(zip(distances,lengths))]

  return o_lens

def load_b64f(path):
  with open(path) as f:
    _b64 = "".join( [ l.rstrip() for l in f.readlines() ] )
    return b64d( _b64 )
