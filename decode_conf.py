#!/usr/bin/python3
from androguard.core.analysis.analysis import ExternalClass
from androguard.core.bytecodes import apk, dvm
from androguard.misc import AnalyzeAPK
from Crypto.Cipher import ARC4


import subprocess
import binascii
import requests
import base64
import string
import sys
import re

apkname = ""
def main(apk, download_module=False):
    global apkname
    apkname = apk
    payload = getRC4Key(apk)
    if payload:
        get_conf(payload,download_module)

def getRC4Key(apk):
    a, d, dx = AnalyzeAPK(apk)
    classes = dx.get_classes()
    for clazz in classes:
        methods = clazz.get_methods()
        for method in methods:
            
            '''
            First step is to find the generator function
            '''
            caller_method = method.get_method()
            if caller_method.get_descriptor() != "([B [B)V":
                continue
            
            source = caller_method.get_source()
            if "length" not in source :
                continue
            

            '''
            Then we can find the key instantiation method by looking at the
            XRef method form the generator
            '''
            caller_xrefs = method.get_xref_from()
            if len(list(caller_xrefs)) != 1:
                print("Error : No XRefs found for PRNG")
                sys.exit(-1)
            
            key_method = list(caller_xrefs)[0][1]
            key_method_source = key_method.get_source()
            
            '''
            Quick regex to find the key
            '''
            keys = re.findall(r"= {(?P<key>(\s*-?\d+,?)+)};", key_method_source)
            if(keys == None):
                print("Error: No key found")
                sys.exit(-1)

            for key in keys:
                key = list(map(lambda x: int(x) & 0xff, key[0].split(",")))
                # print(f"Key : {key}")
                key = bytes(key)
                '''
                Second step : we decrypt the good asset containing the payload
                '''
                resources = a.get_files()
                for res in resources:
                    if ( res.startswith("res/") 
                    or res.startswith("META-INF/")
                    or res == "resource.arsc"
                    or res == "classes.dex" ) :
                        continue
                    else:
                        content = a.get_file(res)
                        rc4 = ARC4.new(key)
                        unciphered_file = rc4.decrypt(content[4:])
                        magic_number = unciphered_file[:2]
                        if( magic_number == b'PK' ):
                            payload_size = int.from_bytes(content[0:4], byteorder = 'little') 
                            # print(f"Filesize : {payload_size}")
                            extract_name = apk + ".payload.apk"
                            f = open(extract_name,"wb")
                            f.write(unciphered_file[:payload_size])
                            f.close()
                            print(f"Saved to : {extract_name}")                         
                            return extract_name

def get_conf(apk, download_module):
    a, d, dx = AnalyzeAPK(apk)

    classes = dx.get_classes()
    for clazz in classes:
        methods = clazz.get_methods()
        
        if(len(methods) != 4):
            continue

        found = False    
        for method in methods:
            '''
            First step is to find the generator function
            '''
            caller_method = method.get_method()
            if caller_method.get_descriptor() != "(Ljava/lang/String;)[B":
                continue
            
            caller_xrefs = method.get_xref_from()
            if len(list(caller_xrefs)) != 1:
                print("Error : not a cerberus sample")
                sys.exit(-1)
            found = True
        
        if found :
            values = []
            url = ""
            for method in methods:
                methodz = method.get_method()
                if methodz.get_descriptor() == "()V":

                    source = methodz.get_source()
                    ciphers = re.findall(r"\(\"(.+)\"\)",source)
                    
                    for cipher in ciphers:
                        pid = subprocess.Popen(["java","Decode",cipher], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        pid.wait()
                        stdout = pid.communicate()[0].decode('utf8').strip()
                        values.append(stdout)
                        
                        if(stdout.startswith("http://") or stdout.startswith("https://")):
                            url = stdout
                            print(f"Found C2 : {url}")
                        #print(cipher+' -> '+ stdout)
            f = open(apkname+".conf","w")
            f.write("\n".join(values))
            f.close()

            if download_module:
                get_module(url,values)

def decrypt(key, cipher):
    return ARC4.new(key).decrypt(binascii.unhexlify(base64.b64decode(cipher)))

def get_module(url,values):
    global apkname
    url = f"{url}/gate.php?action=getModule&data="
    print(f"Downloading module at : {url}")
    cipher = requests.get(url).text
    if(cipher == ""):
        print("Server returned empty module")
        sys.exit(-1)
    
    for i in values:
        clear = decrypt(i,cipher)
        if all(c in string.printable for c in clear) and clear != "":
            f = open(apkname+".module.apk","wb")
            f.write(base64.b64decode(clear))
            f.close()
            sys.exit(-1)

if __name__ == '__main__':
    if(len(sys.argv)!=3):
        print(f'Usage: {sys.argv[0]} <cerberus_apk> <get_remote_module:yes|no>')
        sys.exit(-1)
    main(sys.argv[1], sys.argv[2] == 'yes')