/** 
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 */

var IdentityPolicy = function IdentityPolicy(anchors, rules, chain_limit) {
    this.anchors = anchors != null ? anchors : [];
    this.rules = rules != null ? rules : [];
    this.chain_limit = chain_limit != null ? chain_limit : 10;
};


var VerifyResult = {
SUCCESS: 1,
FAILURE: 2,
TIMEOUT: 3  // Timeout when fetching the key chain
};


/**
 * Recursive verification closure
 * @param {NDN} handle The connected NDN face
 * @param {ContentObject} data The parsed ContentObject to be verified
 * @param {Function} callback The callback function that is called when the verification process finishes.
 *  The prototype for this callback is function (result) {}, where 'result' is a flag indicating the verification result.
 */
IdentityPolicy.prototype.verify = function (handle, data, callback) {
    //console.log('Verify data ' + data.name + ' signed by ' + data.signedInfo.locator.keyName.name.to_uri());

    if (this.anchors.length == 0)
	return false;
    
    var dataStack = [];  // stack to hold unverified content object

    var self = this;

    var chain_length = 0;

    var verifyStack = function (/*Key*/ rootKey) {
	var result;
	var i;
	var key = rootKey;
	for (i = dataStack.length - 1; i >= 0; i--) {
	    var d = dataStack[i];
	    result = d.verify(key);
	    if (result == false)
		break;
	    key = new Key();
	    key.readDerPublicKey(d.content);
	}
	
	if (result == true) {
	    //console.log('Signature verified for content name ' + dataStack[0].name.to_uri());
	    callback(VerifyResult.SUCCESS);
	} else {
	    console.log('Signature verification failed for content name ' + dataStack[i].name.to_uri());
	    console.log('Using public key: \n' + key.publicToDER().toString('hex'));
	    callback(VerifyResult.FAILURE);
	}
    };

    var onData = function (inst, co) {
	chain_length++;
	if (chain_length > self.chain_limit) {
	    console.log('Abort identity verification due to over-limit chain length.');
	    callback(VerifyResult.FAILURE);  // TODO: add a new status flag for this type of failure
	    return;
	}

	var loc = co.signedInfo.locator;
	if (loc.type == KeyLocatorType.KEYNAME) {
	    var keyName = loc.keyName.name;
	    //console.log('Checking key name: ' + keyName.to_uri());
	    // Check policy
	    var anchorKey = self.authorize_by_anchors(co.name, keyName);
	    if (anchorKey != null) {
		dataStack.push(co);
		verifyStack(anchorKey);
		return;
	    }

	    if (self.authorize_by_rules(co.name, keyName) == false) {
		console.log('Verification suspended because policy rule checking failed.');
		callback(VerifyResult.FAILURE);
		return;
	    }

	    // Rule checking passed. Go to fetch the key data.
	    dataStack.push(co);
	    var template = new Interest();
	    template.interestLifetime = 1000;
	    handle.expressInterest(keyName, template, onData, onTimeout);
	} else if (loc.type == KeyLocatorType.KEY) {
	    //console.log('Root key received.');
	    var rootKey = new Key();
	    rootKey.readDerPublicKey(co.content);
	    verifyStack(rootKey);
	} else {
	    // This should not happen.
	    console.log('KeyLocator type is ' + loc.type);
	}
    };
    
    var onTimeout = function (interest) {
	console.log("Interest time out.");
	console.log('Interest name: ' + interest.name.to_uri());
	callback(VerifyResult.TIMEOUT);
    };

    onData(null, data);
};

IdentityPolicy.prototype.authorize_by_anchors = function (/*Name*/ dataName, /*Name*/ keyName) {
    for (var i = 0; i < this.anchors.length; i++) {
	if (keyName.equals(this.anchors[i].key_name)) {
	    var nsp = this.anchors[i].namespace;
	    if (nsp.isPrefixOf(dataName))
		return this.anchors[i].key;
	}
    }
    return null;
};

IdentityPolicy.prototype.authorize_by_rules = function (/*Name*/ dataName, /*Name*/ keyName) {
    var data_name = dataName.to_uri();
    var key_name = keyName.to_uri();
    //console.log(data_name);
    //console.log(key_name);

    for (var i = 0; i < this.rules.length; i++) {
	var rule = this.rules[i];
	if (rule.key_pat.test(key_name) && rule.data_pat.test(data_name)) {
	    var namespace_key = new Name(key_name.replace(rule.key_pat, rule.key_pat_ext));
	    var namespace_data = new Name(data_name.replace(rule.data_pat, rule.data_pat_ext));
	    //console.log('namespace_key: ' + namespace_key.to_uri());
	    //console.log('namespace_data: ' + namespace_data.to_uri());
	    if (namespace_key.isPrefixOf(namespace_data)) {
		return true;
	    }
	}
    }
    
    return false;
};
