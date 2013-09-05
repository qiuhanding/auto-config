var CpsMelnitzPolicy = new IdentityPolicy(
    // anchors
    [
    // Melnitz KSK
	{ key_name: new Name("/ndn/ucla.edu/bms/melnitz/%C1.M.K%00%B1%D2%02V%08%FB%AE%2Bf%3B%D6%E3%83%DDr%CE%9A%98%9F-%BB%BCH%20l%A7hGgni%3E"), 
	  namespace: new Name("/ndn/ucla.edu/bms/melnitz"),
	  key: Key.createFromPEM({ pub: '-----BEGIN PUBLIC KEY-----\n' +
				   'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgEcSG6IMephlNowd6/Y2r5tE8\n' +
				   'bLqp8UC4jbyAcL/g8mNRSjq5umNhoAxVMC6Z7VPcD80AktCWAax+TPSpMunOTM4X\n' +
				   'i/Bxx1mh0xPBga8SL+0kLFN597cGIndbydeWOUWjLBOjwEIatRG53KC7bPlxuUlz\n' + 
				   '120sQdRyXTlms6/yCQIDAQAB\n' + 
				   '-----END PUBLIC KEY-----' }) }
    ],
    // rules
    [
	// rule for 'data' sub-namespace
	{ key_pat: new RegExp("^(/ndn/ucla.edu/bms/melnitz/data)/%FD[^/]+/%C1.M.K[^/]+$"), 
	  key_pat_ext: "$1", 
	  data_pat: new RegExp("^(/ndn/ucla.edu/bms/melnitz/data(?:/[^/]+)*)$"), 
	  data_pat_ext: "$1" },

	// rule for 'kds' sub-namespace
	{ key_pat: new RegExp("^(/ndn/ucla.edu/bms/melnitz/kds)/%FD[^/]+/%C1.M.K[^/]+$"), 
	  key_pat_ext: "$1", 
	  data_pat: new RegExp("^(/ndn/ucla.edu/bms/melnitz/kds(?:/[^/]+)*)$"), 
	  data_pat_ext: "$1" },

	// rule for 'users' sub-namespace
	{ key_pat: new RegExp("^(/ndn/ucla.edu/bms/melnitz/users)/%C1.M.K[^/]+$"), 
	  key_pat_ext: "$1", 
	  data_pat: new RegExp("^(/ndn/ucla.edu/bms/melnitz/users(?:/[^/]+)*)$"), 
	  data_pat_ext: "$1" }
    ]
);
