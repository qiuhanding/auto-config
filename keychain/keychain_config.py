keyfile_folder = 'keys/'

# Hash table mapping key names to key file names
keyfiles = { \
'/ndn/ucla.edu/bms' : 'bms_root.pem', \
'/ndn/ucla.edu/bms/dummy' : 'dummy.pem', \
'/ndn/ucla.edu/bms/dummy/data' : 'data_root.pem', \
'/ndn/ucla.edu/bms/dummy/kds' : 'kds_root.pem', \
'/ndn/ucla.edu/bms/users' : 'user_root.pem', \
'/ndn/ucla.edu/bms/users/public' : 'pub_user.pem', \
'/ndn/ucla.edu/bms/users/qiuhan' : 'qiuhan.pem', \
'/ndn/ucla.edu/bms/users/wentao' : 'wentao.pem' \
}

# Each element in the array is a pair representing (signee_name, signer_name)
# where signer'key signs signee's key
keychain = [ \
('/ndn/ucla.edu/bms', '/ndn/ucla.edu/bms'), \
('/ndn/ucla.edu/bms/users', '/ndn/ucla.edu/bms'), \
('/ndn/ucla.edu/bms/dummy', '/ndn/ucla.edu/bms'), \
('/ndn/ucla.edu/bms/dummy/data', '/ndn/ucla.edu/bms/dummy'), \
('/ndn/ucla.edu/bms/dummy/kds', '/ndn/ucla.edu/bms/dummy'), \
('/ndn/ucla.edu/bms/users/public', '/ndn/ucla.edu/bms/users'), \
('/ndn/ucla.edu/bms/users/qiuhan', '/ndn/ucla.edu/bms/users'), \
('/ndn/ucla.edu/bms/users/wentao', '/ndn/ucla.edu/bms/users')
]

