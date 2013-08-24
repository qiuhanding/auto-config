import os, random, socket
import pyccn
from pyccn import _pyccn

import time
# from time import gmtime, strftime
from threading import Thread
import json
import struct
import random
import kds
from pyccn import _pyccn
import binascii
from Crypto.Cipher import AES
from Crypto import Random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

keyFile = "./keychain/keys/dummy.pem"
key = binascii.unhexlify('389ad5f8fc26f076e0ba200c9b42f669d07066032df8a33b88d49c1763f80783')

class RepoSocketPublisher(pyccn.Closure):
    def __init__(self, repo_port):
        self.repo_dest = ('127.0.0.1', int(repo_port))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.repo_dest)

    def put(self, content):
        self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

class SensorDataLogger():
    def __init__(self, data_interval):
        #Thread.__init__(self)
        self.publisher = RepoSocketPublisher(12345)
        self.prefix = pyccn.Name('/ndn/ucla.edu/bms/dummy/')
        self.interval = data_interval # in milliseconds
		
        self.start_time = int(time.time() * 1000) # time.time() returns float point time in seconds since epoch
		
        if data_interval >= 1000:
            self.aggregate = 1 # put 1 samples in one packet if the interval is large ( may have higher overhead!!! )
        else:
            self.aggregate = int(1000 / data_interval) # limit data rate to be 1 packet per second
		
        self.loadAndPublishKey()
		
		
		
    def loadAndPublishKey(self):
        self.ksk = pyccn.Key()
        self.ksk.fromPEM(filename = keyFile)
        self.ksk_name = self.prefix.appendKeyID(self.ksk)
        self.ksk_si = pyccn.SignedInfo(self.ksk.publicKeyID, pyccn.KeyLocator(self.ksk_name))
		
		
        self.data_dsk = pyccn.Key()
        self.data_dsk.generateRSA(1024)
        self.data_dskname = pyccn.Name("/ndn/ucla.edu/bms/dummy/data").appendVersion().appendKeyID(self.data_dsk)
        self.data_si = pyccn.SignedInfo(self.data_dsk.publicKeyID, pyccn.KeyLocator(self.data_dskname))
        self.publish_dsk(self.data_dsk, self.data_dskname)
        print 'Publish data DSK: ' + str(self.data_dskname)
        
        self.kds_dsk = pyccn.Key()
        self.kds_dsk.generateRSA(1024)
        self.kds_dskname = pyccn.Name("/ndn/ucla.edu/bms/dummy/kds").appendVersion().appendKeyID(self.kds_dsk)
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
        i = 40
        data_dsk_count = 1
        kds_count = 0
        kds_dsk_count = 1
        time_s = struct.pack("!Q", 0)
		
        while (True):
            # now = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
            now = int(time.time() * 1000000000) # in nanoseconds
			
            payload = {'ts': str(now), 'val': random.randint(0,100)}
			
            if kds_count % 120 == 0:
                if kds_dsk_count %2 == 0:
                    self.kds_dsk = pyccn.Key()
                    self.kds_dsk.generateRSA(1024)
                    self.kds_dskname = pyccn.Name("/ndn/ucla.edu/bms/dummy/kds").appendVersion().appendKeyID(self.kds_dsk)
                    self.kds_si = pyccn.SignedInfo(self.kds_dsk.publicKeyID, pyccn.KeyLocator(self.kds_dskname))
                    self.publish_dsk(self.kds_dsk, self.kds_dskname)
                    print 'Publish kds DSK: ' + str(self.kds_dskname)
                    kds_dsk_count = 0
      
                kds_dsk_count = kds_dsk_count + 1
                time_t = int(time.time() * 1000)
                time_s = struct.pack("!Q", time_t)
                
                key = Random.new().read(32)
                kds_thread = kds.KDSPublisher(key, time_s, self.kds_dsk, self.kds_si)
                kds_thread.start()
                kds_count = 0

            kds_count = kds_count + 1
			

            timestamp = struct.pack("!Q", int(int(payload['ts']) / 1000000)) # timestamp is in milliseconds
				
            co = pyccn.ContentObject()
            co.name = self.prefix.append("index").append(timestamp)
            iv = Random.new().read(AES.block_size)
            encryptor = AES.new(key, AES.MODE_CBC, iv)
            co.content = time_s + iv + encryptor.encrypt(pad(json.dumps(payload)))
            co.signedInfo = self.data_si
            co.sign(self.data_dsk)
            self.publisher.put(co)
			
            if data_dsk_count %120 == 0:
                self.data_dsk = pyccn.Key()
                self.data_dsk.generateRSA(1024)
                self.data_dskname = pyccn.Name("/ndn/ucla.edu/bms/dummy/data").appendVersion().appendKeyID(self.data_dsk)
                self.data_si = pyccn.SignedInfo(self.data_dsk.publicKeyID, pyccn.KeyLocator(self.data_dskname))
                self.publish_dsk(self.data_dsk, self.data_dskname)
                print 'Publish data DSK: ' + str(self.data_dskname)
                data_dsk_count = 0
      
            data_dsk_count = data_dsk_count + 1
            
            time.sleep(self.interval / 1000.0)
		
        print "leave child thread"

if __name__ == "__main__":
    print "main thread started..."
    logger = SensorDataLogger(data_interval = 1000)
    logger.run()
    #logger.join()
    print "leave main thread"
	
