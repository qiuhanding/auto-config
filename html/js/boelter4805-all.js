function UnsignedIntToArrayBuffer(value) {
    if (value <= 0)
	return new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    
    // Encode into 64 bits.
    var size = 8;
    var result = new Uint8Array(size);
    var i = 0;
    while (i < 8) {
	//console.log(value);
	++i;
	result[size - i] = value % 256;
	value = Math.floor(value / 256);
    }
    return result;
}

var iv_len = 16;
var key_ts_len = 8;
var data_points = [];
var data_prefix = [];
//var cache_key_ts = -1;
//var cache_key = null;

var onTimeout = function (inst) {
    console.log("Interest timeout: " + inst.name.to_uri());
};

function draw_table() {
    for (var i = 0; i < data_points.length; i++) {
	var name = data_points[i];
	var val_id = '_val';
	var prefix = new Name(name);

	$("#list").append( '<tr><td style="width:75%"></td><td style="width:12%">' 
			   + '</td><td style="width:8%" id="' + val_id + '"></td><td style="width:5%">DUMMY</td></tr>' );
    }
}

function get_all_data() {
    $("#loader").fadeOut(50);
    $("#summary").fadeIn(100);

    draw_table();

    var now = new Date();
    var start = now - 60000; // in milliseconds
    console.log('Fetch data starting from ' + new Date(start) + ' (0x' + start.toString(16) + ')');
    
    var filter = new Exclude([Exclude.ANY, UnsignedIntToArrayBuffer(start)]);
    
    var template = new Interest();
    template.childSelector = 0;
    //template.minSuffixComponent = 1;
    //template.maxSuffixComponent = 2;
    template.interestLifetime = 1000;
    template.exclude = filter;
    
    for (var i = 0; i < data_points.length; i++) {
	(function () {
	    var index = i;
	    var name = data_points[index];
	    var prefix = new Name(name);

	    var display_data = function (obj) {
		//console.log('Trying to show data for ' + bacnet_name);

		var ts = (new Date(obj.ts)).toLocaleTimeString();
		var val = obj.val.toString().substr(0, 6);

		var val_id = '_val';

		$("#" + val_id).text(val);
	    };

	    var processData = function (co, sym_key) {
		var co_name = co.name;
		//console.log(co.name.to_uri());

		var msg = DataUtils.toHex(co.content).substr(key_ts_len * 2);
		var iv = CryptoJS.enc.Hex.parse(msg.substr(0, iv_len * 2));
		var ciphertext = CryptoJS.enc.Hex.parse(msg.substr(iv_len * 2));
		var key = CryptoJS.enc.Hex.parse(sym_key);
		var aesDecryptor = CryptoJS.algo.AES.createDecryptor(key, { iv: iv });
		var p1 = aesDecryptor.process(ciphertext);
		var p2 = aesDecryptor.finalize();
		//console.log(p1.toString(CryptoJS.enc.Utf8));
		//console.log(p2.toString(CryptoJS.enc.Utf8));

		var json_text = p1.toString(CryptoJS.enc.Utf8) + p2.toString(CryptoJS.enc.Utf8);
		var json_obj = jQuery.parseJSON(json_text);

		display_data(json_obj);

		// Send interest for the next content object
		//var tpos = co_name.components.length - 1;
		//var ts = co_name.components[tpos];
		//console.log(ts);

		//var filter = new Exclude([Exclude.ANY, ts]);

		//var template = new Interest();
		//template.childSelector = 0;
		//template.interestLifetime = 1000;
		//template.exclude = filter;

		//setTimeout(function () {ndn.expressInterest(prefix, template, onData, onTimeout); }, 2000);
	    };

	    var fetchDecryptionKey = function (data_co) {
		var key_ts = data_co.content.subarray(0, key_ts_len);
		var key_ts_num = parseInt(DataUtils.toHex(key_ts), 16);

		//if (key_ts_num == cache_key_ts) {
		//    processData(data_co, cache_key);
		//    return;
		//}

		var onKeyData = function (inst, key_co) {
		    //CpsMelnitzPolicy.verify(ndn, key_co, function (result) {
			    //if (result == VerifyResult.SUCCESS) {
				var ciphertext = DataUtils.toHex(key_co.content);
				//console.log(ciphertext);
				var rsa = new RSAKey();
				rsa.readPrivateKeyFromPEMString(ndn.getDefaultKey().privateToPEM());
				var sym_key = rsa.decrypt(ciphertext);
				//console.log(sym_key);
				//cache_key = sym_key;
				//cache_key_ts = key_ts_num;
				processData(data_co, sym_key);
			    //} else if (result == VerifyResult.FAILURE)
				//console.log('Sym key verification failed.');
			    //else if (result == VerifyResult.TIMEOUT)
				//console.log('Sym key verification failed due to timeout.');
			//});
		};

		var onKeyTimeout = function (inst) {
		    console.log('Interest timeout when fetching decryption key:');
		    console.log("Sym key timestamp: " + key_ts_num);
		    console.log(DataUtils.toHex(key_ts));
		    console.log(inst.name.to_uri());
		};
		
		var sym_key_name = new Name('/ndn/ucla.edu/bms/boelter/4805/kds').append(key_ts).appendKeyID(ndn.getDefaultKey());

		var template = new Interest();
		template.interestLifetime = 8000;

		console.log('Fetch sym key: ' + sym_key_name.to_uri());
		ndn.expressInterest(sym_key_name, null, onKeyData, onKeyTimeout);
	    };

	    var onData = function (inst, co) {
		console.log('Inerest name: ' + inst.name.to_uri())
		console.log('Data name: ' + co.name.to_uri());
		//CpsMelnitzPolicy.verify(ndn, co, function (result) {
			//if (result == VerifyResult.SUCCESS) {
			    fetchDecryptionKey(co);
			//} else if (result == VerifyResult.FAILURE)
			//    console.log('Data verification failed.');
			//else if (result == VerifyResult.TIMEOUT)
			//    console.log('Data verification failed due to timeout.');
		    //});
	    };

	    //console.log('Fetch data from ' + name);

	    ndn.expressInterest(prefix, template, onData, onTimeout);
	}) ();
    }
}

var ndn;
var hub = 'localhost';
var count;

var onInitialData = function(inst,co){
    console.log('Getting device list');
    var content = JSON.parse(DataUtils.toString(co.content));
    data_prefix = content.prefix;
    console.log(data_prefix.length);
    for (var i = 0; i<data_prefix.length; i++){
        var data_name = new Name(data_prefix[i])
        ndn.expressInterest(data_name, null, onPointData, onPointTimeout);
        count = i;
        console.log(data_name.to_uri());
    }
    
};

var onPointData = function(inst,co){
    console.log('Getting data points');
    var content = JSON.parse(DataUtils.toString(co.content));
    console.log(content.datapoints);
    for (var i = 0; i < content.datapoints.length; i++)
        data_points.push(content.datapoints[i]);
        //data_points.concat(content.datapoints);
    console.log(data_points[0]);
    console.log(data_points.length);
    if (count == data_prefix.length-1)
        get_all_data(); 
};

var onInitialTimeout = function(inst){
    console.log('Initial Interest Timeout');
};

var onPointTimeout = function(inst){
    console.log('Point Interest Timeout');
};

$(document).ready(function() {
    ndn = new NDN({port:9696, host:hub});
    ndn.onopen = function() { 
        var data_name = new Name('/ndn/ucla.edu/bms/users/public/acl')
        var template = new Interest();
        template.interestLifetime = 2000;
        template.childSelector = 1;
        template.answerOriginKind = 0;
        ndn.expressInterest(data_name, template, onInitialData, onInitialTimeout);
    };
    ndn.connect();
});
