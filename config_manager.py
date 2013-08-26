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
from device_info import device
from pyccn import AOK_NONE

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

handler = pyccn.CCN()
interest_tmpl = pyccn.Interest(scope = 2)
interest_tmpl1 = pyccn.Interest(scope = 2,answerOriginKind = AOK_NONE) 


class RepoSocketPublisher(pyccn.Closure):
    def __init__(self, repo_port):
        self.repo_dest = ('127.0.0.1', int(repo_port))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.repo_dest)

    def put(self, content):
        self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

class ConfigManager():
    def __init__(self):
        self.key = pyccn.Key()
        self.key.fromPEM(filename = './keychain/keys/bms_root.pem')
        self.keyname = pyccn.Name('/ndn/ucla.edu/bms')
        self.publisher = RepoSocketPublisher(12345)
        self.device = device
        self.acl_count = 1
        i = 0
        while i<len(self.device):#add version
            self.device[i]['acl_name'] = str(pyccn.Name(self.device[i]['acl_name']).appendVersion())
            i = i+1

             
    def decoder(self,device_name, serial, code, test, flag):#decoding using the symkey
        k = 0
        for info in self.device:
            if(info['name'] == device_name and info['serial'] == serial):
                iv0 = code[0:16]
                print iv0
                decipher = AES.new(info['symkey'], AES.MODE_CBC, iv0)
                text = unpad(decipher.decrypt(code[16:len(code)]))
                print text
                print test
                if text == test:
                    if flag == 'interest':
                        self.device[k]['loc_name'] = test
                        content = {'acl_name':info['acl_name'],'prefix':info['prefix'],'trust_anchor':[{'name':str(self.keyname.appendKeyID(self.key)),'namespace':str(self.keyname),'pubkey':str(self.key.publicToPEM())}]}
                        print content
                        txt = json.dumps(content)
                        iv = Random.new().read(AES.block_size)
                        cipher = AES.new(info['symkey'], AES.MODE_CBC, iv)
                        ciphertxt = cipher.encrypt(pad(txt))
                        sendtxt = iv+ciphertxt
                        return sendtxt
                    elif flag =='data':
                        self.device[k]['pubkey'] = test
                        return info['prefix']
                else:
                    print "decode failure"
                    return None
            k = k+1
            
        return None
    def find(self,device_name,serial):
        i = 0
        for info in self.device:
            if(info['name'] == device_name and info['serial'] == serial):
                return i
            i = i+1
        return -1
    def run(self):
        for info in self.device:
            co_name = pyccn.Name(info['acl_name'])
            print str(co_name)
            content = json.dumps({'acl':info['acl']})
            co = pyccn.ContentObject(name = co_name, content = content, signed_info = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.keyname)))
            co.sign(self.key)
            self.publisher.put(co)
        InterestBaseName = pyccn.Name('/local/manager')
        configclosure = ConfigClosure(self)
        handler.setInterestFilter(InterestBaseName, configclosure)
        while True:
            handler.run(500)
            if self.acl_count%60 == 0:
                self.acl_count = 0;
                i = 0
                while i<len(self.device):
                    self.device[i]['acl_name'] =pyccn.Name(self.device[i]['acl_name']).components
                    co_name = pyccn.Name(self.device[i]['acl_name'][0:len(self.device[i]['acl_name'])-1]).appendVersion()
                    print 'publish acl to repo'
                    print str(co_name)
                    self.device[i]['acl_name'] = str(co_name)
                    self.device[i]['acl'] = self.device[i]['acl'][0:2]##
                    content = json.dumps({'acl':self.device[i]['acl']})##
                    co = pyccn.ContentObject(name = co_name, content = content, signed_info =   pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.keyname)))
                    co.sign(self.key)
                    self.publisher.put(co)
                    inst_name = pyccn.Name(self.device[i]['loc_name']).append('acl')
                    aclclosure = ConfigClosure(self)
                    handler.expressInterest(inst_name,aclclosure,interest_tmpl1)
                    print 'manager expressInterest'
                    print inst_name
                    i = i+1
            self.acl_count = self.acl_count+1
            time.sleep(1.0)
                
        
        
        
        
#need setInterestFilter
class ConfigClosure(pyccn.Closure):
    def __init__(self,cm):
        self.cm = cm
    def upcall(self, kind, upcallInfo):
        if kind == pyccn.UPCALL_CONTENT or kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
            co = upcallInfo.ContentObject
            print 'manager on data'
            print str(co.name)
            if co.name.components[len(co.name.components)-1]=='pubkey':
                device_name = co.name.components[len(co.name.components)-3]
                serial = co.name.components[len(co.name.components)-2]
                test = co.signedInfo.keyLocator.key.publicToDER()
                prefix = self.cm.decoder(device_name,serial,co.content,test,'data')
                if(prefix != None):
                    keyname = pyccn.Name(prefix).appendVersion().appendKeyID(co.signedInfo.keyLocator.key)
                    content = pyccn.ContentObject(name = keyname, content = test, signed_info = pyccn.SignedInfo(self.cm.key.publicKeyID, pyccn.KeyLocator(self.cm.keyname)))
                    content.sign(self.cm.key)
                    self.cm.publisher.put(content)
                    print 'publish G\'s public key to repo'
            #elif co.name.components[len(co.name.components)-1]=='acl':
                #verify?
                   
        elif kind == pyccn.UPCALL_INTEREST:
            interest = upcallInfo.Interest
            print 'manager on interest'
            print interest.name
            if interest.name.components[len(interest.name.components)-1]!='acl':
                device_name = interest.name.components[len(interest.name.components)-3]
                serial = interest.name.components[len(interest.name.components)-2]
                info = interest.name.components[len(interest.name.components)-1]
                test = interest.name.components[2:len(interest.name.components)-1]
                test = str(pyccn.Name(test))
                sendtxt = self.cm.decoder(device_name,serial,info,test,'interest')
                print 'sendtxt:'
                print sendtxt
                if(sendtxt!=-1):
                    co = pyccn.ContentObject(name = interest.name, content = sendtxt, signed_info = pyccn.SignedInfo(self.cm.key.publicKeyID, pyccn.KeyLocator(self.cm.keyname)))
                    co.sign(self.cm.key)
                    handler.put(co)
                    #express interest for pubkey with the prefix it receive as well as listen acl
                    inst_name = pyccn.Name(test).append('pubkey')
                    #dataclosure = ConfigClosure()
                    handler.expressInterest(inst_name,self,interest_tmpl)
                    print 'M express Interest'
                    print inst_name
            else:
                device_name = interest.name.components[len(interest.name.components)-3]
                serial = interest.name.components[len(interest.name.components)-2]
                index = self.cm.find(device_name,serial)
                if index!=-1:
                    acl_name = self.cm.device[index]['acl_name']
                    print 'acl_name:'+acl_name
                    co = pyccn.ContentObject(name = interest.name, content = acl_name, signed_info = pyccn.SignedInfo(self.cm.key.publicKeyID, pyccn.KeyLocator(self.cm.keyname)))
                    co.sign(self.cm.key)
                    handler.put(co)
                #it's the acl interest asking
                
                
        elif kind == pyccn.UPCALL_INTEREST_TIMED_OUT:
            return pyccn.RESULT_REEXPRESS

        return pyccn.RESULT_OK
        
    


    
if __name__ == "__main__":
    print "main thread started..."
    cm = ConfigManager()
    cm.run()
    print "leave main thread"
