#!/usr/bin/env python

"""
Encoder for replacer's config file
Author: LiPeK (lipek002@gmail.com)
"""

from sys import (argv, exc_info)
from os import system
from shutil import copy
try:
    from hashlib import md5
except ImportError:
    from md5 import md5
from Crypto.Cipher import XOR
import binascii

# CONFIG_URL is base64 encoded url address of encrypted config file.
# The same url should be set in dtella/common/replacer.py file.
# It is used as XOR cipher key
CONFIG_URL = binascii.b2a_base64("http://host/replacer.enc")
print "CONFIG_URL = " + repr(CONFIG_URL)

cfg_file = "replacer.cfg"
enc_file = cfg_file.rsplit('.',1)[0]+'.enc'

try:
    f = open(cfg_file,'r')
except:
    print "File %s not found." % cfg_file
    exit()

config = None
try:
    config = f.readlines()
except:
    print "Cannot read file: %s" % cfg_file
    exit()
f.close()

try:
    key = md5()
    key.update(CONFIG_URL)
    key = key.hexdigest()
    hash = md5()
    xor = XOR.new(key)
    _config = []
    for line in config:
        if line[0] in '#\r\n':
            continue
        line = line.strip()
        if line == '':
            continue
        line = line.decode('utf-8','replace').encode('cp1250','replace')
        hash.update(line)
        _config.append(binascii.hexlify(xor.encrypt(line))+'\n')
    config = _config
    print "Config hashed and encrypted.\nNew hash: %s" % hash.hexdigest()
except:
    print "Unable to encrypt or hash config"
    print exc_info()
    exit()

try:
    f = open(enc_file,'w')
except:
    print "Cannot open file for writing: %s" % enc_file
    exit()

try:
    f.write(hash.hexdigest()+'\n')
    f.writelines(config)
except:
    print "Cannot write file: %s" % enc_file
    exit()
f.close()

system('touch last_encoded')

print "Config file updated."
