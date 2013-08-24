import pyccn
from pyccn import _pyccn

import user_list

from threading import Thread
import struct
import socket

import binascii
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

import re

handler = pyccn.CCN()

interest_tmpl = pyccn.Interest(scope = 1)

flag_terminate = 0

class RepoSocketPublisher:
    def __init__(self, repo_port):
        self.repo_dest = ('127.0.0.1', int(repo_port))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.repo_dest)

    def put(self, content):
        self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

class VerificationClosure(pyccn.Closure):
    def __init__(self, roster, key, timestamp, dsk, dsk_si):
        self.kds_key = dsk
        self.kds_si = dsk_si
        self.prefix = pyccn.Name('/ndn/ucla.edu/bms/dummy/kds')
        self.symkey = key
        self.roster = roster
        self.index = 0
        self.timestamp = timestamp
        self.publisher = RepoSocketPublisher(12345)
        self.anchors = [{'name':'/ndn/ucla.edu/bms/dummy/%C1.M.K%00b%23%95%EC%BE%0E%5E%D3%D3%E8%C6Ja%EEH%FBr%F5%AB%91%83R%9B.%B3l%C8%09%06%9EIu','namespace': '/ndn/ucla.edu/bms/dummy', 'pubkey': \
                             '0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x000\x81\x89\x02\x81\x81\x00\xaf\xed\xf3\x1a\xabkK\xd1\xb8\x0f\x95Z\xd8\xbc\xc9\xda\xe1\x07\xaf\xbdl\xff\xc9\xeb\x9b+\xfd\xde6\xdfw\xa2%\x04\x86\x00\x12\xc5>\x8f\x9e8\xfc%jg\xfaG\xa6\x8d\x96\x9b\xc5\xa6q\xcb\xa3j`\x95\xa48Q\xa0a\xe6\xf1\xa3\xc4\x8d\xa3\xf6)\xef\xd6S\xb4\x96q\xca\xcc&\x87\xe7\x0f>\xcc\xbc\x8cb}gb\xeb+9f\x8b\xe5C/OdWjp\x04\x8f\xf4Mc\xd1\x15\xc24\xad\xc5\xc6\x7f\xe2*aqz\x83\x0b@\xff\x02\x03\x01\x00\x01' \
        }]
        self.rules = [
	#rule for 'users' sub-namespace
	{ 'key_pat': re.compile("^(/ndn/ucla.edu/bms/dummy/users)/%C1.M.K[^/]+$"), 'key_pat_ext': 0, 'data_pat': re.compile("^(/ndn/ucla.edu/bms/dummy/users(?:/[^/]+)*)$"), 'data_pat_ext': 0 }]
        self.stack = []

    def authorize_by_anchor (self, data_name, key_name):
        for anchor in self.anchors:
            if key_name == anchor['name']:
                namespace_key = anchor['namespace']
                if namespace_key[:] == data_name[0:len (namespace_key)]:
                    return anchor['pubkey']
            
        return None

    def authorize_by_rule (self, data_name, key_name): 
        for rule in self.rules:
            matches_key = rule['key_pat'].match(key_name)
            if matches_key != None:
                matches_data = rule['data_pat'].match(data_name)
            
                if matches_data != None:
                    namespace_key_t = rule['key_pat'].findall(key_name)
                    namespace_key = namespace_key_t[rule['key_pat_ext']]
                    namespace_data_t =  rule['data_pat'].findall(data_name)
                    namespace_data = namespace_data_t[rule['data_pat_ext']]
                
                    if len (namespace_key) == 0 or namespace_key[:] == namespace_data[:len (namespace_key)]:
                        return True
        return False


    def upcall(self, kind, upcallInfo):
        global flag_terminate
        if kind == pyccn.UPCALL_CONTENT or kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
            co = upcallInfo.ContentObject
            
            keylocator =str(co.signedInfo.keyLocator.keyName)
            anchor_pubkey = self.authorize_by_anchor(str(co.name),keylocator)
            if anchor_pubkey !=None:
                root_key = pyccn.Key()
                root_key.fromDER(public = anchor_pubkey)
                flag = co.verify_signature(root_key)
                while flag == True and len(self.stack)>0:
                    key = pyccn.Key()
                    key.fromDER(public = co.content)
                    flag =  self.stack[len(self.stack)-1].verify_signature(key)
                    
                    co = self.stack.pop()
                
                if len(self.stack) == 0:
                    usrpubkey = co.content
                    #publish
                    usrkey = pyccn.Key()
                    usrkey.fromDER(public = usrpubkey)
                    key_t = RSA.importKey(usrpubkey)
                    cipher = PKCS1_v1_5.new(key_t)
                    ciphertext = cipher.encrypt(self.symkey)
                    
                    userdataname = self.prefix.append(self.timestamp).appendKeyID(usrkey)
                    CO = pyccn.ContentObject(name = userdataname,content = ciphertext,signed_info = self.kds_si)
                    CO.sign(self.kds_key)

                    self.publisher.put(CO)
                    print CO.name

                    self.index = self.index+1
                    if self.index<len(self.roster):
                        nextname = pyccn.Name(self.roster[self.index])
                        handler.expressInterest(nextname,self,interest_tmpl)
                    
                    else:
                        #print "overrrrrrrrrr"
                        flag_terminate = 1
                        #print flag_terminate

            elif self.authorize_by_rule(str(co.name),keylocator)==True:
                self.stack.append(co)
                handler.expressInterest(pyccn.Name(keylocator),self,interest_tmpl)
            else:
                print "verification failed"
                flag_terminate = 1
                
        elif kind == pyccn.UPCALL_INTEREST_TIMED_OUT:
            return pyccn.RESULT_REEXPRESS

        return pyccn.RESULT_OK

    
    
    

class KDSPublisher(Thread):
    def  __init__(self, symkey, timestamp, dsk, dsk_si):
        Thread.__init__(self)
        self.symkey = binascii.hexlify(symkey)
        self.timestamp = timestamp
        self.dsk = dsk
        self.dsk_si = dsk_si

    def run(self):
        global flag_terminate
        print 'Publisher started...'
        closure = VerificationClosure(user_list.usrlist, self.symkey, self.timestamp, self.dsk, self.dsk_si)
        first = pyccn.Name(user_list.usrlist[0]);

        handler.expressInterest(first, closure, interest_tmpl)

        while(flag_terminate == 0):
            handler.run(500)
            #print flag_terminate

        print 'Publisher stop'
        flag_terminate = 0
            
      


       
                
