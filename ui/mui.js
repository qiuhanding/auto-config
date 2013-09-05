var ndn = new NDN();

// For test purpose
function defaultVal() {
    $('#uname').val('/ndn/ucla.edu/bms/users/test');

    var pem = '-----BEGIN PUBLIC KEY-----\n' + 
	'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC041RcFNZxXweFGdQpMp6BAS+p\n' + 
	'f2VSs3tNFIvhceMcBRVwUDecD0YFiEJtb5a/yKd/A3860NYRxGnKTJb68/M+3vkH\n' + 
	'hxeiMN9XPo357wQrAXMq0xWpo1C+A4htYwDsXR0Qt61/O2r8toVXVWeClm/25hnj\n' + 
	'kezKiJWA/aRXMr6dSwIDAQAB\n' + 
	'-----END PUBLIC KEY-----';
    
    $('#pubkey').val(pem);
    
    $('#data_prefix').val('/ndn/ucla.edu/bms/boelter/4809');
}

var mui_prefix = '/local/bms/mui'
//var connected = false;

var onInterest = function (inst) {
    //connected = true;
    console.log('onInterest: ' + inst.name.to_uri());
    var uname = $('#uname').val();
    console.log(uname);
    var pubkeypem = $('#pubkey').val();
    console.log(pubkeypem);
    var key = new Key();
    key.fromPem(pubkeypem);
    var data_prefix = $('#data_prefix').val();
    console.log(data_prefix);
    data_prefix = data_prefix.split();
    var content = { name: uname, pubkey: DataUtils.toHex(key.publicToDER()), data_prefix: data_prefix};
    console.log(content);
    var co = new ContentObject(inst.name, JSON.stringify(content));
    co.sign(ndn.getDefaultKey());
    ndn.send(co);
    console.log('Data sent');
};

var n = new Name('/local/manager' + mui_prefix + '/' + (new Date()).getTime() + '/userreg');
var template = new Interest();
template.interestLifetime = 1000;
template.answerOriginKind = 0;

var initialInterestTimeout = function (inst) {
//    if (connected == false)
//	ndn.expressInterest(n, template, null, initialInterestTimeout);
    console.log('Initial Interest timeout: ' + inst.name.to_uri());
};

ndn.onopen = function () {
    ndn.registerPrefix(new Name(mui_prefix), onInterest);
    ndn.expressInterest(n, template, null, initialInterestTimeout);
    console.log('Initial interest sent.');
};

function submit() {
    ndn.connect();
}