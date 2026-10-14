from modules.crypto_core import hashing, MLDSA, MLKEM
#We use complicated form of transfer of data to simulate safe data transfer using zeroconf, and finally TCP

#Alice will genereate the public signature key and the public kem key
alice_pub_sign_key = MLDSA().generate_key('pub')
alice_sign_key_hash = hashing.hash_convert_str(hashing.hash_key(alice_pub_sign_key))
storage = {"ali_sgn_hash": alice_sign_key_hash}

#Testing the secret_key input during Instantiation


#BOB will use randomly created secret_key for creating his profile. We also assume storage instantly transports objects between alice and bob
rand_key = MLDSA().generate_key('pvt')
bob_pub_sign_key = MLDSA(rand_key).generate_key('pub')
bob_sign_key_hash = hashing.hash_convert_str(hashing.hash_key(bob_pub_sign_key))
storage['bob_sgn_hash'] = bob_sign_key_hash


#Bob and alice both have each other's hash now 
#alice screen : 
bob_sign_hash = storage.pop('bob_sgn_hash')
storage['ali_pub_key']= alice_pub_sign_key

#Bob screen : 
alice_sign_hash = storage.pop('ali_sgn_hash')
alice_pub_key = storage.pop('ali_pub_key')
hash_key_bytes = hashing.hash_convert_bytes(alice_sign_hash)
if hashing.hash_verify(alice_pub_key, hash_key_bytes):
    print("hellowww!! hash_verified")
    storage['bob_pub_key'] = bob_pub_sign_key
else: 
    print('FAILESDDDD')
    raise Exception("hash error")

#alice screen :
bob_pub_key = storage.pop('bob_pub_key')
hash_key_bytes = hashing.hash_convert_bytes(bob_sign_hash)
if hashing.hash_verify(bob_pub_key, hash_key_bytes):
    print("hellowww!! hash_verified")
else: 
    print('FAILESDDDD')
    raise Exception("hash error")
    
 