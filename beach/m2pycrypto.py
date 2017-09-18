#!/usr/bin/env python
#
# Copyright (c) 2013 Carl Scharenberg <carl.scharenberg@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__all__ = ['SecretError', 'NoDataError', 'DecryptionError', 'EncryptionError',
           'PasswordError', 'Secret']

"""
Small utility and module for encrypting and decrypting data using symmetric-key
algorithms. By default uses 256-bit AES (Rijndael) using CBC, but some options
are configurable. PBKDF2 algorithm used to derive key from password.

Sample uses: passwords in INI files, password manager, encrypted files
"""

import os
import sys
import hmac
from hashlib import sha256
from binascii import hexlify, unhexlify

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


version = '0.1'
version_info = tuple([int(x) for x in version.split('.')])


class SecretError(Exception):
    """
    Base class for Secret-specific errors.
    """


class NoDataError(SecretError):
    """
    This exception will be raised if we don't have data to encrypt/decrypt.
    """


class DecryptionError(SecretError):
    """
    Failed to decrypt. Can happen with wrong password, for example.
    """


class EncryptionError(SecretError):
    """
    Failed to encrypt.
    """


class PasswordError(SecretError):
    """
    Problem with password(s).
    """


class Secret:
    """
    Stores a secret and has ways to decrypt the secret and set new secret.

    @warning: Once password is in memory, it will be possible
              to get the ciphertext as well. This may be possible
              even after the password is cleared due to Python memory
              management.
    @warning: If the password is used, secret will be decrypted and available
              in plain text in memory, possibly even after it has been
              explicitly cleared after use.
    @warning: If weak password is used, the
              encryption will not be of much help.
    """

    def __init__(self, iv=None, salt=None, ciphertext=None,
                 iterations=1000, algorithm='aes_256_cbc'):
        """
        Construct a Secret object.

        ciphertext, iv and salt can be None when originally created. The Secret
        is then considered to not hold any data. To set new data, call
        encrypt().

        @param iv: The IV, 256 bits (byte string 32 long)
        @param salt: The salt, 256 bits (byte string 32 long)
        @param ciphertext: The secret to hold
        @param iterations: The number of iterations to use with PBKDF2,
                           recommend 1000.
        @param param: The algorithm to use, recommend aes_256_cbc.
        """
        self.ciphertext = ciphertext
        self.iv = iv or os.urandom(32)
        self.salt = salt or os.urandom(32)
        self.iterations = iterations
        self.algorithm = algorithm

    def decrypt(self, password):
        """
        Decrypt.

        @param password: The password to decrypt data with.
        @return: Decrypted data
        """
        if not self.ciphertext or not self.iv or not self.salt or \
                        password is None:
            raise NoDataError

        # If the password is callable we'll assume it will return the
        # real password.
        try:
            password = password()
        except TypeError:
            pass

        # the crypto algorithms are unicode unfriendly
        if isinstance(password, unicode):
            password = password.encode('utf8')

        # derive 256 bit key using the pbkdf2 standard
        key = PBKDF2(password, self.salt, dkLen=32, count=self.iterations)

        # Derive encryption key and HMAC key from it
        # See Practical Cryptography section 8.4.1.
        hmacKey = sha256(key + 'MAC').digest()
        encKey = sha256(key + 'encrypt').digest()
        del key

        # decrypt
        try:
            ret = decrypt(self.ciphertext, encKey, self.iv, self.algorithm)
        except Exception, e:
            # TODO Identify a more specific error to catch. For M2Crypto, was "EVP.EVPError"
            raise EncryptionError(str(e))
        finally:
            del encKey

        # Check MAC
        mac = ret[-64:]
        ret = ret[:-64]
        try:
            if hmac.new(hmacKey, ret + self.iv + self.salt,
                        sha256).hexdigest() != mac:
                raise DecryptionError('HMAC does not match')
        finally:
            del hmacKey

        return ret

    def encrypt(self, cleartext, password):
        """
        Encrypt.

        @param cleartext: The data to encrypt.
        @param password: The password to encrypt data with.
        @return: Encrypted data
        """
        if cleartext is None or password is None:
            raise NoDataError

        # If the password is callable we'll assume it will return the
        # real password.
        try:
            password = password()
        except TypeError:
            pass

        # the crypto algorithms are unicode unfriendly
        if isinstance(password, unicode):
            password = password.encode('utf8')

        # derive 256 bit encryption key using the pbkdf2 standard
        key = PBKDF2(password, self.salt, dkLen=32, count=self.iterations)

        # Derive encryption key and HMAC key from it
        # See Practical Cryptography section 8.4.1.
        hmacKey = sha256(key + 'MAC').digest()
        encKey = sha256(key + 'encrypt').digest()
        del key

        # Add HMAC to cleartext so that we can check during decrypt if we got
        # the right cleartext back. We are doing sign-then-encrypt, which let's
        # us encrypt empty cleartext (otherwise we'd need to pad with some
        # string to encrypt). Practical Cryptography by Schneier & Ferguson
        # also recommends doing it in this order in section 8.2.
        mac = hmac.new(hmacKey,
                       cleartext + self.iv + self.salt,
                       sha256).hexdigest()
        del hmacKey

        # encrypt
        try:
            self.ciphertext = encrypt(cleartext + mac, encKey, self.iv,
                                      self.algorithm)
        except Exception, e:
            # TODO Identify a more specific error to catch. For M2Crypto, was "EVP.EVPError"
            raise EncryptionError(str(e))

        return self.ciphertext

    def serialize(self, serialize=None):
        """Serialize secret.

        @param serialize: None or callable that must accept string to serialize
        @return: Serialized string
        """
        if not self.ciphertext or not self.iv or not self.salt:
            raise NoDataError

        serialized = "%s|%s|%s" % (hexlify(self.iv), hexlify(self.salt),
                                   hexlify(self.ciphertext))
        if serialize is not None:
            serialize(serialized)
        return serialized

    def deserialize(self, deserialize):
        """Deserialize secret.

        @param deserialize: String or callable that must return the serialized form.
        """
        try:
            serialized = deserialize()
        except TypeError:
            serialized = deserialize

        iv, salt, ciphertext = serialized.split('|')
        self.iv, self.salt, self.ciphertext = unhexlify(iv), unhexlify(salt), unhexlify(ciphertext)

    def clear(self):
        try:
            del self.ciphertext
        except AttributeError:
            pass
        try:
            del self.iv
        except AttributeError:
            pass
        try:
            del self.salt
        except AttributeError:
            pass


def pkcs7_encode(text, k=16):
    """Pad text out to k-byte blocks with PKCS#7 algorithm."""
    n = k - (len(text) % k)
    return text + unhexlify(n * ("%02x" % n))


def pkcs7_decode(text, k=16):
    """Remove pad characters from text encoded with PKCS#7 algorithm."""
    if len(text) == 0:
        raise ValueError("Empty string implies incorrect padding")
    n = int(hexlify(text[-1]), 16)
    if n > k:
        raise ValueError("Input is not padded or padding is corrupt")
    return text[:-n]


def decrypt(ciphertext, key, iv, alg):
    """
    Decrypt ciphertext
    """
    assert len(key) == len(iv) == 32
    cipher = AES.new(key=key, mode=AES.MODE_CBC, IV=iv[:16])
    del key
    plaintext = pkcs7_decode(cipher.decrypt(ciphertext))
    return plaintext


def encrypt(plaintext, key, iv, alg):
    """
    Encrypt plaintext
    """
    assert len(key) == len(iv) == 32
    cipher = AES.new(key=key, mode=AES.MODE_CBC, IV=iv[:16])
    del key
    ciphertext = cipher.encrypt(pkcs7_encode(plaintext))
    assert ciphertext
    return ciphertext


def get_password(confirm=True):
    """get password"""
    import getpass

    password = getpass.getpass('password:')
    if confirm:
        if getpass.getpass('password (again):') != password:
            raise PasswordError('Passwords do not match')
    return password


def main():
    from optparse import OptionParser

    usage = 'usage: %prog [options]'
    parser = OptionParser(usage=usage,
                          version='%prog ' + version,
                          description='Encrypt or decrypt data with password using 256 bit AES (Rijndael) encryption in CBC mode. Key derived from password with PBKDF2 algorithm using 1000 iterations.')
    parser.add_option('-d', '--decrypt',
                      action='store_true', dest='decrypt', default=False,
                      help="Decryption mode.")
    parser.add_option('-e', '--encrypt',
                      action='store_true', dest='encrypt', default=False,
                      help="Encryption mode.")
    parser.add_option('-i', '--in',
                      dest='infile', metavar='INFILE',
                      help='INFILE to read in. Without this options reads stdin.')
    parser.add_option('-o', '--out',
                      dest='outfile', metavar='OUTFILE',
                      help="OUTFILE to output into. Without this option prints to stdout.")
    parser.add_option('-p', '--password',
                      metavar='PASSWORD', dest='password',
                      help="Supply PASSWORD from the command line (otherwise will be prompted for). Try to not use this option, since it is safer to be prompted for password.")

    (options, args) = parser.parse_args()
    if (options.decrypt and options.encrypt) or (not options.decrypt and not options.encrypt):
        parser.print_help()
        sys.exit(1)

    if not options.infile:
        options.args = ''.join(sys.stdin.readlines())
    else:
        options.args = ''

    if options.encrypt:
        secret = Secret()
        secret.encrypt(options.args or open(options.infile, 'rb').read(),
                       options.password or get_password)
        if options.outfile:
            f = open(options.outfile, 'wb')
            secret.serialize(f.write)
            f.close()
        else:
            secret.serialize(sys.stdout.write)
    else:
        secret = Secret()
        secret.deserialize((options.args or open(options.infile, 'rb').read()).strip())
        cleartext = secret.decrypt(options.password or (lambda: get_password(confirm=False)))
        if options.outfile:
            f = open(options.outfile, 'wb')
            f.write(cleartext)
            f.close()
        else:
            sys.stdout.write(cleartext)


if __name__ == "__main__":
    main()