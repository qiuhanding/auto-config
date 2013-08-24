import pyccn
from pyccn import _pyccn

import socket

import keychain_config

class RepoSocketPublisher:
    def __init__(self, repo_port):
        self.repo_dest = ('127.0.0.1', int(repo_port))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.repo_dest)

    def put(self, content):
        self.sock.send(_pyccn.dump_charbuf(content.ccn_data))

publisher = RepoSocketPublisher(12345)

for pair in keychain_config.keychain:
    signee_name = pair[0]
    signer_name = pair[1]
    
    signee_keyfile = keychain_config.keyfile_folder + keychain_config.keyfiles[signee_name]
    signer_keyfile = keychain_config.keyfile_folder + keychain_config.keyfiles[signer_name]
    
    signee_key = pyccn.Key()
    signee_key.fromPEM(filename = signee_keyfile)
    signer_key = pyccn.Key()
    signer_key.fromPEM(filename = signer_keyfile)
    
    signee_name = pyccn.Name(signee_name).appendKeyID(signee_key)
    signer_name = pyccn.Name(signer_name).appendKeyID(signer_key)

    key_co = pyccn.ContentObject()
    key_co.name = signee_name
    key_co.content = signee_key.publicToDER()
    key_co.signedInfo = pyccn.SignedInfo(signer_key.publicKeyID, pyccn.KeyLocator(signer_name), type = pyccn.CONTENT_KEY, final_block = b'\x00')
    key_co.sign(signer_key)
    
    publisher.put(key_co)

