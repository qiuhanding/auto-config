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
import hashlib
from user_list import usrlist

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

handler = pyccn.CCN()
interest_tmpl = pyccn.Interest(scope = 2,answerOriginKind = AOK_NONE) 


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
        self.keyname = pyccn.Name('/ndn/ucla.edu/bms').appendKeyID(self.key)
        self.publisher = RepoSocketPublisher(12345)
        self.device = device
        self.usrlist = usrlist
        self.acl_count = 1
        self.acl_tree = None
        self.FormAclTree()
        self.GenerateAcl()
        self.dsk = pyccn.Key()
        self.dsk.fromPEM(filename = './keychain/keys/user_root.pem')
        self.dskname = pyccn.Name('/ndn/ucla.edu/bms/users').appendKeyID(self.dsk)
        i = 0
        while i<len(self.device):#add version
            self.device[i]['acl_name'] = str(pyccn.Name(self.device[i]['acl_name']).appendVersion())
            i = i+1
            
    def FormAclTree(self):
        self.acl_tree = dict([('/ndn/ucla.edu/bms',{'acl':[],'child':['/ndn/ucla.edu/bms/melnitz','/ndn/ucla.edu/bms/boelter']}), \
        ('/ndn/ucla.edu/bms/melnitz',{'acl':[],'child':['/ndn/ucla.edu/bms/melnitz/1405']}), \
        ('/ndn/ucla.edu/bms/boelter',{'acl':[],'child':['/ndn/ucla.edu/bms/boelter/4805','/ndn/ucla.edu/bms/boelter/4809']}), \
        ('/ndn/ucla.edu/bms/melnitz/1405',{'acl':[],'child':[]}), \
        ('/ndn/ucla.edu/bms/boelter/4805',{'acl':[],'child':[]}), \
        ('/ndn/ucla.edu/bms/boelter/4809',{'acl':[],'child':[]})])
        
        for usr in usrlist:
            for prefix in usr['prefix']:
                name_t = pyccn.Name(prefix)
                if (len(name_t.components) > 5):
                    name_t = pyccn.Name(name_t.components[0:5])
                if ((str(name_t) in self.acl_tree) == True):
                    self.acl_tree[str(name_t)]['acl'].append(usr['usrname'])

    def AddUser(self,user):
        for prefix in user['prefix']:
            name_t = pyccn.Name(str(prefix))
            if (len(name_t.components) > 5):
                name_t = pyccn.Name(name_t.components[0:5])
            name_str = str(name_t)
            if ((name_str in self.acl_tree) == True):
                self.acl_tree[name_str]['acl'].append(user['usrname'])
                #len_name = len(name_t.components)
                self.node = []
                self.find_device(name_str)
                for device_name in self.node:
                    index = self.findbyprefix(device_name)
                    if(index != -1):
                        self.device[index]['acl'].append(user['usrname'])
                        self.update_acl(index)
                
    def update_acl(self,index):
        self.device[index]['acl_name'] =pyccn.Name(self.device[index]['acl_name']).components
        co_name = pyccn.Name(self.device[index]['acl_name'][0:len(self.device[index]['acl_name'])-1]).appendVersion()
                        
        print 'publish acl to repo'
        print str(co_name)
        self.device[index]['acl_name'] = str(co_name)
        content = json.dumps({'acl':self.device[index]['acl']})##
        co = pyccn.ContentObject(name = co_name, content = content, signed_info =   pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.keyname)))
        co.sign(self.key)
        self.publisher.put(co)
        if(self.device[index]['loc_name']!=None):
            inst_name = pyccn.Name(self.device[index]['loc_name']).append('acl')
            aclclosure = ConfigClosure(self)
            handler.expressInterest(inst_name,aclclosure,interest_tmpl)
            print 'manager expressInterest'
            print inst_name
                            
    def find_device(self,rootname):
        child = self.acl_tree[rootname]['child']
        if (len(child) == 0):
            self.node.append(rootname)
        else:
            for childname in child:
               self.find_device(childname)
            

    def GenerateAcl(self):
        j = 0
        for device in self.device:
            k = 3
            name_t = pyccn.Name(device['prefix'])
            while (k<=len(name_t.components)):
                temp = str(pyccn.Name(name_t.components[0:k]))
                if((temp in self.acl_tree) == True):
                    for acl_t in self.acl_tree[temp]['acl']:
                        self.device[j]['acl'].append(acl_t)
                k = k+1
            j = j+1
                    
                           
            

             
    def decoder(self,device_name, serial, code, test, flag):#decoding using the symkey
        k = 0
        for info in self.device:
            if(info['name'] == device_name and info['serial'] == serial):
                iv0 = code[0:16]
                #print iv0
                decipher = AES.new(info['symkey'], AES.MODE_CBC, iv0)
                text = unpad(decipher.decrypt(code[16:len(code)]))
                m = hashlib.sha256()
                m.update(test)
                digest = m.hexdigest()
                #print 'text'
                #print text
                #print 'test'
                #print test
                #print digest
                if text == digest:
                    if flag == 'interest' and self.device[k]['loc_name'] == None:
                        self.device[k]['loc_name'] = test
                        content = {'acl_name':info['acl_name'],'prefix':info['prefix'],'trust_anchor':[{'name':str(self.keyname),'namespace':str(pyccn.Name(self.keyname.components[0:len(self.keyname.components)-1])),'pubkey':str(self.key.publicToPEM())}]}
                        print content
                        txt = json.dumps(content)
                        iv = Random.new().read(AES.block_size)
                        m = hashlib.sha256()
                        m.update(txt)
                        cipher = AES.new(info['symkey'], AES.MODE_CBC, iv)
                        ciphertxt = cipher.encrypt(pad(m.hexdigest()))
                        sendtxt = json.dumps({'uncripted':txt,'ciphertxt':binascii.hexlify(iv+ciphertxt)})
                        return sendtxt
                    elif flag =='data' and self.device[k]['pubkey'] == None:
                        self.device[k]['pubkey'] = test
                        return info['prefix']
                else:
                    print "decode failure"
                    return None
            k = k+1
            
        return None
        
    def findbyprefix(self,prefix):
        i = 0
        for info in self.device:
            if(info['prefix'] == prefix):
                return i
            i = i+1
        return -1
        
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
            print info['acl']
            content = json.dumps({'acl':info['acl']})
            co = pyccn.ContentObject(name = co_name, content = content, signed_info = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.keyname)))
            co.sign(self.key)
            self.publisher.put(co)
        InterestBaseName = pyccn.Name('/local/manager')
        configclosure = ConfigClosure(self)
        handler.setInterestFilter(InterestBaseName, configclosure)
        for usr in self.usrlist:
            name_t = pyccn.Name(str(usr['usrname'])).components
            username = pyccn.Name(name_t[0:len(name_t)-1]).append('acl').appendVersion()
            device_prefix = []
            
            for prefix in usr['prefix']:
                name_t = pyccn.Name(str(prefix))
                if (len(name_t.components) > 5):
                    name_t = pyccn.Name(name_t.components[0:5])
                name_str = str(name_t)
                if ((name_str in self.acl_tree) == True):
                    self.node = []
                    self.find_device(name_str)
                    #print self.node
                    for device_name in self.node:
                        #print device_name
                        index = self.findbyprefix(device_name)
                        flag = (device_name+'/data_points') in device_prefix
                        #print (index != -1 and flag == False)
                        if (index != -1 and flag == False):
                            device_prefix.append(device_name+'/data_points')            
            
            print device_prefix
            data_prefix = pyccn.ContentObject(name = username, content = json.dumps({'prefix':device_prefix}), signed_info = pyccn.SignedInfo(self.key.publicKeyID, pyccn.KeyLocator(self.keyname)))
            data_prefix.sign(self.dsk)
            self.publisher.put(data_prefix)
            print 'Publish Data Points'
            print username              
        
        while True:
            handler.run(1000)
            #if self.acl_count == 60:
            #    user = {'usrname':'/ndn/ucla.edu/bms/users/wentao', 'prefix':['/ndn/ucla.edu/bms/boelter/4809/electrical']}
            #    self.usrlist.append(user)
            #    self.AddUser(user)
                
            #self.acl_count = self.acl_count+1
        
        
        
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
                print 'publicToDER'
                print test
                prefix = self.cm.decoder(device_name,serial,co.content,test,'data')
                if(prefix != None):
                    keyname = pyccn.Name(prefix).appendVersion().appendKeyID(co.signedInfo.keyLocator.key)
                    content = pyccn.ContentObject(name = keyname, content = test, signed_info = pyccn.SignedInfo(self.cm.key.publicKeyID, pyccn.KeyLocator(self.cm.keyname)))
                    content.sign(self.cm.key)
                    self.cm.publisher.put(content)
                    print 'publish G\'s public key to repo'
            elif co.name.components[len(co.name.components)-1] != 'acl':
                content = json.loads(co.content)
                userkey = pyccn.Key()
                userkey.fromDER(public=binascii.unhexlify(content['pubkey']))
                userkey_co = pyccn.ContentObject()
                userkey_co.name = pyccn.Name(str(content['name'])).appendKeyID(userkey)
                userkey_co.content = binascii.unhexlify(content['pubkey'])
                userkey_co.signedInfo = pyccn.SignedInfo(self.cm.dsk.publicKeyID,    pyccn.KeyLocator(self.cm.dskname), type = pyccn.CONTENT_KEY, final_block = b'\x00')
                userkey_co.sign(self.cm.dsk)
                self.cm.publisher.put(userkey_co)
                newuser = {'usrname':str(userkey_co.name), 'prefix':content['data_prefix']}
                self.cm.usrlist.append(newuser)
                self.cm.AddUser(newuser)
                
                device_prefix = []
                name_t = pyccn.Name(str(content['name'])).components
                username = pyccn.Name(name_t[0:len(name_t)-1]).append('acl').appendVersion()
                for prefix in content['data_prefix']:
                    name_t = pyccn.Name(str(prefix))
                    if (len(name_t.components) > 5):
                        name_t = pyccn.Name(name_t.components[0:5])
                    name_str = str(name_t)
                    if ((name_str in self.cm.acl_tree) == True):
                        self.cm.node = []
                        self.cm.find_device(name_str)
                        
                        for device_name in self.cm.node:
                            index = self.cm.findbyprefix(device_name)
                            print (device_name+'/data_points') in device_prefix
                            if(index != -1 and ((device_name+'/data_points') in device_prefix == False)):
                                device_prefix.append(device_name+'/data_points')
                data_prefix = pyccn.ContentObject(name = username, content = json.dumps({'prefix':device_prefix}), signed_info = pyccn.SignedInfo(self.cm.key.publicKeyID, pyccn.KeyLocator(self.cm.keyname)))
                data_prefix.sign(self.cm.dsk)
                self.cm.publisher.put(data_prefix)
            #elif co.name.components[len(co.name.components)-1]=='acl':
                #verify?
                   
        elif kind == pyccn.UPCALL_INTEREST:
            interest = upcallInfo.Interest
            print 'manager on interest'
            print interest.name
            if interest.name.components[len(interest.name.components)-1]=='userreg':
                user_prefix = pyccn.Name(interest.name.components[2:len(interest.name.components)-1])
                print user_prefix
                handler.expressInterest(user_prefix,self,interest_tmpl)
            elif interest.name.components[len(interest.name.components)-1]!='acl':
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
            print 'Reexpress interest'
            return pyccn.RESULT_REEXPRESS

        return pyccn.RESULT_OK
        
    


    
if __name__ == "__main__":
    print "main thread started..."
    cm = ConfigManager()
    cm.run()
    print "leave main thread"
