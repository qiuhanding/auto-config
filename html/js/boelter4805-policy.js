var CpsMelnitzPolicy = new IdentityPolicy(
    // anchors
    [
    // Melnitz KSK
	{ key_name: new Name("/ndn/ucla.edu/bms/boelter/4805/%C1.M.K%00%40m%F8%A5%BA%14%86%F4%90%E3%DC%28%1C7%FChU%0F%27VM%5B%C8%28%14%2F%DC%FC%CCA%D5%D2"), 
	  namespace: new Name("/ndn/ucla.edu/bms/boelter/4805"),
	  key: Key.createFromPEM({ pub: '-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAMVpvn8WvO6wQ4GwG0XLKpAj9NyjX2kwr8eGUQc4OEUMujsLob2LCqqU\nYDt2n41QC1+h7DHRX4v407Zkir4rMcoMgVr/XqNo6IQbNwEV7c+lYO4cRKdlav48\nTZ/J5e46YZ8RH62ELEetfhmiCQm70NPMm+JiPfHMkwGrfZK5QCEvAgMBAAE=\n-----END RSA PUBLIC KEY-----\n' }) }
    ],
    // rules
    [
	// rule for 'data' sub-namespace
	{ key_pat: new RegExp("^(/ndn/ucla.edu/bms/boelter/4805/data)/%FD[^/]+/%C1.M.K[^/]+$"), 
	  key_pat_ext: "$1", 
	  data_pat: new RegExp("^(/ndn/ucla.edu/bms/boelter/4805/data(?:/[^/]+)*)$"), 
	  data_pat_ext: "$1" },

	// rule for 'kds' sub-namespace
	{ key_pat: new RegExp("^(/ndn/ucla.edu/bms/boelter/4805/kds)/%FD[^/]+/%C1.M.K[^/]+$"), 
	  key_pat_ext: "$1", 
	  data_pat: new RegExp("^(/ndn/ucla.edu/bms/boelter/4805/kds(?:/[^/]+)*)$"), 
	  data_pat_ext: "$1" },

	// rule for 'users' sub-namespace
	{ key_pat: new RegExp("^(/ndn/ucla.edu/bms/users)/%C1.M.K[^/]+$"), 
	  key_pat_ext: "$1", 
	  data_pat: new RegExp("^(/ndn/ucla.edu/bms/users(?:/[^/]+)*)$"), 
	  data_pat_ext: "$1" }
    ]
);
