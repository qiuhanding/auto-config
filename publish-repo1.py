import os, random, socket
import pyccn
from pyccn import _pyccn

import time
# from time import gmtime, strftime
from threading import Thread
import threading
import json
import struct
import random
import kds
from pyccn import _pyccn
import binascii
from Crypto.Cipher import AES
from Crypto import Random
from pyccn import AOK_NONE
import hashlib

interest_tmpl = pyccn.Interest(scope = 2, childSelector = 1, answerOriginKind = AOK_NONE, interestLifetime = 1000.0)
interest_tmpl0 = pyccn.Interest(scope = 2)
handler0 = pyccn.CCN()
flag_terminate0 = 0

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

keyFile = "./keychain/keys/boelter4809.pem"
key = binascii.unhexlify('14fe923dd3ac6e8945ea02e892db6b3192f2081cbab26b44147d308af58f5609')
time_s = None

ksk = pyccn.Key()
ksk.generateRSA(1024)

serial = '002'
symkey = '\x8a\x1c\xe7\x8c\xd5\xdae#:\x91H\xfbU\xfc\x83\x19\xb9\xfeQH5\xcf$\x99\x84R\xcf\x11y\n1\xff'

class RepoSocketPublisher(pyccn.Closure):
    def __init__(self, repo_port):
        self.repo_dest = ('127.0.0.1', int(repo_port))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.repo_dest)

    def put(self, content):
        self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

class SensorDataLogger(Thread):
    def __init__(self, data_interval,trust_anchor,prefix):
        Thread.__init__(self)
        self.publisher = RepoSocketPublisher(12345)
        self.prefix = pyccn.Name(str(prefix))
        print 'SensorDataLogger.init: ' + str(type(self.prefix))
        self.interval = data_interval # in milliseconds
        self.acl = None
        #self.lock = threading.Lock()
		
        self.start_time = int(time.time() * 1000) # time.time() returns float point time in seconds since epoch
		
        if data_interval >= 1000:
            self.aggregate = 1 # put 1 samples in one packet if the interval is large ( may have higher overhead!!! )
        else:
            self.aggregate = int(1000 / data_interval) # limit data rate to be 1 packet per second
        
        self.anchor = trust_anchor
        self.data_prefix = self.prefix.append('index')
        
        self.loadAndPublishKey()
		
		
    def loadAndPublishKey(self):
        self.ksk = pyccn.Key()
        self.ksk.generateRSA(1024)
        #self.ksk.fromPEM(filename = keyFile)
        self.ksk_name = self.prefix.appendKeyID(self.ksk)
        self.ksk_si = pyccn.SignedInfo(self.ksk.publicKeyID, pyccn.KeyLocator(self.ksk_name))
		
		
        self.data_dsk = pyccn.Key()
        self.data_dsk.generateRSA(1024)
        self.data_dskname = self.prefix.append('data').appendVersion().appendKeyID(self.data_dsk)
        self.data_si = pyccn.SignedInfo(self.data_dsk.publicKeyID, pyccn.KeyLocator(self.data_dskname))
        self.publish_dsk(self.data_dsk, self.data_dskname)
        print 'Publish data DSK: ' + str(self.data_dskname)
        
        self.kds_dsk = pyccn.Key()
        self.kds_dsk.generateRSA(1024)
        self.kds_dskname = self.prefix.append('kds').appendVersion().appendKeyID(self.kds_dsk)
        self.kds_si = pyccn.SignedInfo(self.kds_dsk.publicKeyID, pyccn.KeyLocator(self.kds_dskname))
        self.publish_dsk(self.kds_dsk, self.kds_dskname)
        print 'Publish data DSK: ' + str(self.kds_dskname)
	
    def publish_dsk(self,dsk, dsk_name):
        key_con = pyccn.ContentObject()
        key_con.name = dsk_name
        key_con.content = dsk.publicToDER()
        key_con.signedInfo = pyccn.SignedInfo(self.ksk.publicKeyID, pyccn.KeyLocator(self.ksk_name), type = pyccn.CONTENT_KEY, final_block = b'\x00')
        key_con.sign(self.ksk)
        self.publisher.put(key_con)

		
    def run(self):
        #print "child thread started..."
        # For test purpose, run for 10 seconds only
        # Push content to repo every second
        global key, time_s
        i = 40
        data_dsk_count = 1
        kds_count = 0
        kds_dsk_count = 1
        point_count = 0
        time_s = struct.pack("!Q", 0)
		
        while (True):
            # now = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
            now = int(time.time() * 1000000000) # in nanoseconds
			
            payload = {'ts': str(now), 'val': random.randint(0,100)}
			
            if kds_count % 120 == 0:
                if kds_dsk_count %2 == 0:
                    self.kds_dsk = pyccn.Key()
                    self.kds_dsk.generateRSA(1024)
                    self.kds_dskname = self.prefix.append("kds").appendVersion().appendKeyID(self.kds_dsk)
                    self.kds_si = pyccn.SignedInfo(self.kds_dsk.publicKeyID, pyccn.KeyLocator(self.kds_dskname))
                    self.publish_dsk(self.kds_dsk, self.kds_dskname)
                    print 'Publish kds DSK: ' + str(self.kds_dskname)
                    kds_dsk_count = 0
      
                kds_dsk_count = kds_dsk_count + 1
                time_t = int(time.time() * 1000)
                time_s = struct.pack("!Q", time_t)
                
                key = Random.new().read(32)
                kds_thread = kds.KDSPublisher(key, time_s, self.kds_dsk, self.kds_si, self.anchor, self.acl, self.kds_dskname)#, self.lock)
                kds_thread.start()
                kds_count = 0

            kds_count = kds_count + 1
			

            timestamp = struct.pack("!Q", int(int(payload['ts']) / 1000000)) # timestamp is in milliseconds
				
            co = pyccn.ContentObject()
            co.name = self.data_prefix.append(timestamp)
            iv = Random.new().read(AES.block_size)
            encryptor = AES.new(key, AES.MODE_CBC, iv)
            co.content = time_s + iv + encryptor.encrypt(pad(json.dumps(payload)))
            co.signedInfo = self.data_si
            co.sign(self.data_dsk)
            self.publisher.put(co)
			
            if data_dsk_count %120 == 0:
                self.data_dsk = pyccn.Key()
                self.data_dsk.generateRSA(1024)
                self.data_dskname = self.prefix.append('data').appendVersion().appendKeyID(self.data_dsk)
                self.data_si = pyccn.SignedInfo(self.data_dsk.publicKeyID, pyccn.KeyLocator(self.data_dskname))
                self.publish_dsk(self.data_dsk, self.data_dskname)
                print 'Publish data DSK: ' + str(self.data_dskname)
                data_dsk_count = 0
      
            data_dsk_count = data_dsk_count + 1
            
            time.sleep(self.interval / 1000.0)
		
        print "leave child thread"

class InitialClosure(pyccn.Closure):
    #def __init__(self):
    
    def upcall(self, kind, upcallInfo):
    
        if kind == pyccn.UPCALL_CONTENT or kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
            print 'G on data'
            co = upcallInfo.ContentObject
            device_prefix = co.content.strip(' \t\n\r')+'/device/siemens/'+serial
            #how to append serial
            #register prefix device_name
            print device_prefix
            InterestBaseName = pyccn.Name(device_prefix).append('pubkey')
            configclosure = ConfigClosure(device_prefix)###################
            handler0.setInterestFilter(InterestBaseName, configclosure)
            m = hashlib.sha256()
            m.update(device_prefix)
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(symkey, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(m.hexdigest()))
            instname = pyccn.Name('/local/manager'+device_prefix).append(iv+ciphertext)
            #configclosure1 = ConfigClosure()
            handler0.expressInterest(instname,configclosure,interest_tmpl0)
                
        elif kind == pyccn.UPCALL_INTEREST_TIMED_OUT:
            print 'interest time out'
            return pyccn.RESULT_REEXPRESS
        return pyccn.RESULT_OK
            
            
            
class ConfigClosure(pyccn.Closure):
    def __init__(self,device_prefix):
        self.device_prefix = device_prefix
        self.logger = None
    def upcall(self, kind, upcallInfo):
        if kind == pyccn.UPCALL_CONTENT or kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
            co = upcallInfo.ContentObject
            #how to decript
            print 'G on data'
            co_content = json.loads(co.content)
            encrypted_content = binascii.unhexlify(co_content['ciphertxt'])
            iv = encrypted_content[0:16]
            ciphertxt = encrypted_content[16:len(encrypted_content)]
            decipher = AES.new(symkey, AES.MODE_CBC, iv)
            txt = unpad(decipher.decrypt(ciphertxt))
            m = hashlib.sha256()
            m.update(co_content['uncripted'])
            if txt == m.hexdigest() and self.logger == None:
                content = json.loads(co_content['uncripted'])
                print 'content'
                print content
                aclname = pyccn.Name(str(content['acl_name']))
                print aclname
                self.logger = SensorDataLogger(1000,content['trust_anchor'],content['prefix'])
                aclclosure = AclClosure(self.logger,self.device_prefix)
                handler0.expressInterest(aclname,aclclosure,interest_tmpl0)
                InterestBaseName = pyccn.Name(self.device_prefix).append('acl')
                print InterestBaseName
                handler0.setInterestFilter(InterestBaseName, aclclosure)
                
        elif kind == pyccn.UPCALL_INTEREST:
            print 'G on interest'
            interest = upcallInfo.Interest
            print interest.name
            pubkey = ksk.publicToDER()
            iv = Random.new().read(AES.block_size)
            m = hashlib.sha256()
            m.update(pubkey)
            digest = m.hexdigest()
            cipher = AES.new(symkey, AES.MODE_CBC, iv)
            cipherkey = cipher.encrypt(pad(digest))
            print 'digest'
            print digest
            sendpubkey = pyccn.Key()
            sendpubkey.fromDER(public = pubkey)
            co = pyccn.ContentObject(name = interest.name, content = iv+cipherkey, signed_info = pyccn.SignedInfo(ksk.publicKeyID, pyccn.KeyLocator(sendpubkey), type = pyccn.CONTENT_KEY, final_block = b'\x00') )####################
            co.sign(ksk)  
            handler0.put(co)
        elif kind == pyccn.UPCALL_INTEREST_TIMED_OUT:
            return pyccn.RESULT_REEXPRESS

        return pyccn.RESULT_OK
        


class AclClosure(pyccn.Closure):
    def __init__(self,logger,device_prefix):
        self.logger = logger
        self.device_prefix = device_prefix
    def upcall(self, kind, upcallInfo):
        if kind == pyccn.UPCALL_CONTENT or kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
            co = upcallInfo.ContentObject
            root_key = pyccn.Key()
            root_key.fromPEM(public = self.logger.anchor[0]['pubkey'])
            flag = co.verify_signature(root_key)
            if flag == True:
                if co.name.components[len(co.name.components)-1] == 'acl':
                    print 'getting acl name'
                    inst_name = pyccn.Name(str(co.content))
                    handler0.expressInterest(inst_name,self,interest_tmpl)
                elif co.name.components[len(co.name.components)-2] == 'acl':
                    print 'getting acl'
                    if self.logger.acl == None:
                        self.logger.acl = json.loads(co.content)['acl']
                        self.logger.start()
                    else:
                        #self.logger.lock.acquire()
                        self.logger.acl = json.loads(co.content)['acl']
                        #self.logger.lock.release()
                        kds_thread = kds.KDSPublisher(key, time_s, self.logger.kds_dsk, self.logger.kds_si, self.logger.anchor, self.logger.acl, self.logger.kds_dskname)#,self.logger.lock)
                        kds_thread.start()
                        #I need to trigger the kds to fetch symkey########
                #self.logger.join()
        elif kind == pyccn.UPCALL_INTEREST:
            interest = upcallInfo.Interest
            content = 'received'
            co = pyccn.ContentObject(name = interest.name,content = content,signed_info = pyccn.SignedInfo(ksk.publicKeyID,pyccn.KeyLocator(self.logger.ksk_name)) )
            co.sign(ksk)
            handler0.put(co)
            inst_name = pyccn.Name('/local/manager'+self.device_prefix).append('acl')
            handler0.expressInterest(inst_name,self,interest_tmpl0)
        elif kind == pyccn.UPCALL_INTEREST_TIMED_OUT:
            return pyccn.RESULT_REEXPRESS

        return pyccn.RESULT_OK
    


    
if __name__ == "__main__":
    print "main thread started..."
    n0 = pyccn.Name('/local/ndn/prefix')
    closure = InitialClosure()
    handler0.expressInterest(n0,closure,interest_tmpl)
    
    #device_prefix = '/ndn/ucla.edu/irl/device/siemens/'+serial
    #how to append serial
    #register prefix device_name
    #print device_prefix
    #InterestBaseName = pyccn.Name(device_prefix).append('pubkey')
    #configclosure = ConfigClosure()###################
    #handler0.setInterestFilter(InterestBaseName, configclosure)
    #iv = Random.new().read(AES.block_size)
    #cipher = AES.new(symkey, AES.MODE_CBC, iv)
    #ciphertext = cipher.encrypt(pad(device_prefix))
    #instname = pyccn.Name('/local/manager'+device_prefix).append(iv+ciphertext)
    #configclosure1 = ConfigClosure()
    #handler0.expressInterest(instname,configclosure,interest_tmpl0)
    
    
    while True:
        handler0.run(500)
    #logger.join()
    print "leave main thread"
	
