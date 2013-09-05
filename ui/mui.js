var ndn = new NDN();

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