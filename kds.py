import pyccn
from pyccn import _pyccn

#import user_list

from threading import Thread
import struct
import socket

import binascii
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

import re

handler = pyccn.CCN()

interest_tmpl = pyccn.Interest(scope = 2)

flag_terminate = 0

class RepoSocketPublisher:
    def __init__(self, repo_port):
        self.repo_dest = ('127.0.0.1', int(repo_port))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.repo_dest)

    def put(self, content):
        self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

class VerificationClosure(pyccn.Closure):
    def __init__(self, acl, key, timestamp, dsk, dsk_si, anchor, prefix):
        self.kds_key = dsk
        self.kds_si = dsk_si
        self.prefix = pyccn.Name(prefix)
        self.symkey = key
        self.acl = acl
        self.index = 0
        self.timestamp = timestamp
        self.publisher = RepoSocketPublisher(12345)
        self.anchors = anchor
        self.acl = acl
        print 'acl'
        print acl
        #[{'name':'/ndn/ucla.edu/bms/%C1.M.K%00%03a%27%95_%7C%1F%CD%C0E%2B54%00%87%AC%84r%DBg%83%07%5D%F9%03%02p%DB%A9%B8%06%B4','namespace': '/ndn/ucla.edu/bms', 'pubkey': \
        #                     '0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x000\x81\x89\x02\x81\x81\x00\xd8\xe8\xa76\xbe|\x99\x1f\x0eO\x8e\xbel\xc1\xed\xfd-p\x8b>\xb1\x0f-\x1b\xf7z#j\xba\x9c\x0c\xa0\x9bh\x08\xfbg\xab\x89\xc7\xb5\xc5\xdb\xde\x90H\xee(F\x17\x86\xaf\xd6O\x12`\x00\xd2)n\x95\x14IV\x1e\xa6\xf4+\xa4\xed1z\x801\x1d\x7f\xbe\xcf3\xd3\xbc\xa7\x83\xda\xe6\x13~\x1e\xc3\xb6\x86\xae\xc96\x16\x8e":c\xa4eg\x11\x85\xa2\xff\xae\xa1\xe4\xc6s28W3\'S.\x87\xc5\x94\'\xf7\x90\xa9\x888c\x02\x03\x01\x00\x01' \
        #}]
        self.rules = [
	#rule for 'users' sub-namespace
	{ 'key_pat': re.compile("^(/ndn/ucla.edu/bms/users)/%C1.M.K[^/]+$"), 'key_pat_ext': 0, 'data_pat': re.compile("^(/ndn/ucla.edu/bms/users(?:/[^/]+)*)$"), 'data_pat_ext': 0 }]
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
                root_key.fromPEM(public = anchor_pubkey)
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
                    if self.index<len(self.acl):
                        nextname = pyccn.Name(str(self.acl[self.index]))
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
    def  __init__(self, symkey, timestamp, dsk, dsk_si, anchor, acl, prefix):#, lock):
        Thread.__init__(self)
        self.symkey = binascii.hexlify(symkey)
        self.timestamp = timestamp
        self.dsk = dsk
        self.dsk_si = dsk_si
        self.anchor = anchor
        self.acl = acl
        self.prefix = prefix
        #self.lock = lock

    def run(self):
        global flag_terminate
        print 'Publisher started...'
        closure = VerificationClosure(self.acl, self.symkey, self.timestamp, self.dsk, self.dsk_si,self.anchor, self.prefix)
        first = pyccn.Name(str(self.acl[0]))
        print first

        handler.expressInterest(first, closure, interest_tmpl)
        #self.lock.acquire()
        count = 0
        while(flag_terminate == 0):
            handler.run(500)
            count = count+1
            if(count == 60):
            #print flag_terminate
                break
            #if(count<60):
            #self.lock.release()
        print 'Publisher stop'
        flag_terminate = 0
            
      


       
                
