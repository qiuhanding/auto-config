keyfile_folder = 'keys/'

# Hash table mapping key names to key file names
keyfiles = { \
'/ndn/ucla.edu/bms' : 'bms_root.pem', \
'/ndn/ucla.edu/bms/boelter' : 'boelter.pem', \
'/ndn/ucla.edu/bms/boelter/4805': 'boelter4805.pem', \
'/ndn/ucla.edu/bms/boelter/4805/data' : 'data_root.pem', \
'/ndn/ucla.edu/bms/boelter/4805/kds' : 'kds_root.pem', \
'/ndn/ucla.edu/bms/boelter/4809': 'boelter4809.pem', \
'/ndn/ucla.edu/bms/boelter/4809/data' : 'data_root4809.pem', \
'/ndn/ucla.edu/bms/boelter/4809/kds' : 'kds_root4809.pem', \
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
('/ndn/ucla.edu/bms/boelter', '/ndn/ucla.edu/bms'), \
('/ndn/ucla.edu/bms/boelter/4805', '/ndn/ucla.edu/bms/boelter'), \
('/ndn/ucla.edu/bms/boelter/4805/data', '/ndn/ucla.edu/bms/boelter/4805'), \
('/ndn/ucla.edu/bms/boelter/4805/kds', '/ndn/ucla.edu/bms/boelter/4805'), \
('/ndn/ucla.edu/bms/boelter/4809', '/ndn/ucla.edu/bms/boelter'), \
('/ndn/ucla.edu/bms/boelter/4809/data', '/ndn/ucla.edu/bms/boelter/4809'), \
('/ndn/ucla.edu/bms/boelter/4809/kds', '/ndn/ucla.edu/bms/boelter/4809'), \
('/ndn/ucla.edu/bms/users/public', '/ndn/ucla.edu/bms/users'), \
('/ndn/ucla.edu/bms/users/qiuhan', '/ndn/ucla.edu/bms/users'), \
('/ndn/ucla.edu/bms/users/wentao', '/ndn/ucla.edu/bms/users')
]

