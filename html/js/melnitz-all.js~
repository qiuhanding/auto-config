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
//var cache_key_ts = -1;
//var cache_key = null;

var onTimeout = function (inst) {
    console.log("Interest timeout: " + inst.name.to_uri());
};

function draw_table() {
    for (var i = 0; i < data_points.length; i++) {
	var name = data_points[i].name;
	var bacnet_name = data_points[i].lable;
	var name_id = bacnet_name.replace(/\./g, '_') + '_name';
	var ts_id = bacnet_name.replace(/\./g, '_') + '_ts';
	var val_id = bacnet_name.replace(/\./g, '_') + '_val';
	var prefix = new Name(name);
	var unit = data_points[i].unit;

	$("#list").append( '<tr><td style="width:75%" id="' + name_id + '">' + bacnet_name + '</td><td style="width:12%" id="' + ts_id + '">' 
			   + '</td><td style="width:8%" id="' + val_id + '"></td><td style="width:5%">' + unit + '</td></tr>' );
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
	    var name = data_points[index].name;
	    var bacnet_name = data_points[index].lable;
	    var prefix = new Name(name);
	    var unit = data_points[index].unit;

	    var name_id = bacnet_name.replace(/\./g, '_') + '_name';
	    $("#" + name_id).hover(
		function () { $("#" + name_id).text(name); },
		function () { $("#" + name_id).text(bacnet_name); }
		);

	    $("#" + name_id).click(function () {
		    window.open('./melnitz.html#' + index, '_self');
		});

	    var display_data = function (obj) {
		//console.log('Trying to show data for ' + bacnet_name);

		var ts = (new Date(obj.ts)).toLocaleTimeString();
		var val = obj.val.toString().substr(0, 6);

		var ts_id = bacnet_name.replace(/\./g, '_') + '_ts';
		var val_id = bacnet_name.replace(/\./g, '_') + '_val';

		$("#" + ts_id).text(ts);
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
		    CpsMelnitzPolicy.verify(ndn, key_co, function (result) {
			    if (result == VerifyResult.SUCCESS) {
				var ciphertext = DataUtils.toHex(key_co.content);
				//console.log(ciphertext);
				var rsa = new RSAKey();
				rsa.readPrivateKeyFromPEMString(ndn.getDefaultKey().privateToPEM());
				var sym_key = rsa.decrypt(ciphertext);
				//console.log(sym_key);
				//cache_key = sym_key;
				//cache_key_ts = key_ts_num;
				processData(data_co, sym_key);
			    } else if (result == VerifyResult.FAILURE)
				console.log('Sym key verification failed.');
			    else if (result == VerifyResult.TIMEOUT)
				console.log('Sym key verification failed due to timeout.');
			});
		};

		var onKeyTimeout = function (inst) {
		    console.log('Interest timeout when fetching decryption key:');
		    console.log("Sym key timestamp: " + key_ts_num);
		    console.log(DataUtils.toHex(key_ts));
		    console.log(inst.name.to_uri());
		};
		
		var sym_key_name = new Name('/ndn/ucla.edu/bms/melnitz/kds').append(key_ts).appendKeyID(ndn.getDefaultKey());

		var template = new Interest();
		template.interestLifetime = 8000;

		//console.log('Fetch sym key: ' + sym_key_name.to_uri());
		ndn.expressInterest(sym_key_name, null, onKeyData, onKeyTimeout);
	    };

	    var onData = function (inst, co) {
		console.log('Inerest name: ' + inst.name.to_uri())
		console.log('Data name: ' + co.name.to_uri());
		CpsMelnitzPolicy.verify(ndn, co, function (result) {
			if (result == VerifyResult.SUCCESS) {
			    fetchDecryptionKey(co);
			} else if (result == VerifyResult.FAILURE)
			    console.log('Data verification failed.');
			else if (result == VerifyResult.TIMEOUT)
			    console.log('Data verification failed due to timeout.');
		    });
	    };

	    //console.log('Fetch data from ' + name);

	    ndn.expressInterest(prefix, template, onData, onTimeout);
	}) ();
    }
}

var ndn;
var hub = 'localhost';

$(document).ready(function() {
    ndn = new NDN({port:9696, host:hub});
    ndn.onopen = function() { get_all_data(); };
    ndn.connect();
});
