# This does not make sense yet!

M2CRYPTO = False
IV_LENGTH = 0x10
try:
    import M2Crypto
    M2CRYPTO = True
except:
    print( "Beach crypto facilities reverted due to failure to load M2Crypto." )

if not M2CRYPTO:
    from beach.m2pycrypto import Secret
    #from Crypto.Cipher import AES



