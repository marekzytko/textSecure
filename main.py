import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, constant_time
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.serialization import NoEncryption, Encoding, PrivateFormat, PublicFormat


#Za:
#https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf

"""5.1. Integration with X3DH
The Double Ratchet algorithm can be used in combination with the X3DH key
agreement protocol [1]. The Double Ratchet plays the role of a “post-X3DH”
protocol which takes the session key SK negotiated by X3DH and uses it as the
Double Ratchet’s initial root key.
The following outputs from X3DH are used by the Double Ratchet:
• The SK output from X3DH becomes the SK input to Double Ratchet
initialization (see Section 3.3).
• The AD output from X3DH becomes the AD input to Double Ratchet
encryption and decryption (see Section 3.4 and Section 3.5).
• Bob’s signed prekey from X3DH (SPKB) becomes Bob’s initial ratchet
public key (and corresponding key pair) for Double Ratchet initialization.
Any Double Ratchet message encrypted using Alice’s initial sending chain can
serve as an “initial ciphertext” for X3DH. To deal with the possibility of lost or
out-of-order messages, a recommended pattern is for Alice to repeatedly send
the same X3DH initial message prepended to all of her Double Ratchet messages
until she receives Bob’s first Double Ratchet response message."""



class State():
    def __init__(self):
        self.DHs = None
        self.DHr = None
        self.RK = None
        self.CKs = None
        self.CKr = None
        self.Ns = None
        self.Nr = None
        self.PN = None
        self.MKSKIPPED = None


class DoubleRatchet():
    #FIXME
    # Unknown correct value - random '5' for testing purposes.
    MAX_SKIP = 5
    def __init__(self):
        self.state = State()
    
    def GENERATE_DH(self) -> (bytes, bytes):
        """Returns a new Diffie-Hellman key pair.
        
        This function is recommended to generate a key
pair based on the Curve25519 or Curve448 elliptic curves"""

        # Generate a private key for use in the exchange.
        private_key = X448PrivateKey.generate()
        peer_public_key = X448PrivateKey.generate().public_key()
        
        return (private_key.private_bytes(
                    encoding=Encoding.Raw,
                    format=PrivateFormat.Raw,
                    encryption_algorithm=NoEncryption()
                    ),
                peer_public_key.public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw
                    )
                )
    
    def DH(self, dh_pair, dh_pub):
        """Returns the output from the Diffie-Hellman
calculation between the private key from the DH key pair dh_pair and
the DH public key dh_pub. If the DH function rejects invalid public keys,
then this function may raise an exception which terminates processing.

This function is recommended to return the
output from the X25519 or X448 function as defined in [7]. There is no
need to check for invalid public keys"""
        ...
    
    def KDF_RK(self, rk, dh_out) -> (bytes, bytes):
        """Returns a pair (32-byte root key, 32-byte chain
key) as the output of applying a KDF keyed by a 32-byte root key rk to a
Diffie-Hellman output dh_out.

This function is recommended to be implemented using HKDF [3] with SHA-256 or SHA-512 [8], using rk as HKDF
salt, dh_out as HKDF input key material, and an application-specific byte
sequence as HKDF info. The info value should be chosen to be distinct
from other uses of HKDF in the application."""
        #TODO
        #Check if possible to replace with PBKDF2HMAC or Scrypt
        if rk == None:
            rk = os.urandom(32)
        kdf = HKDF(
            backend=default_backend,
            algorithm=hashes.SHA512(),
            length=64,
            salt=rk,
            #TODO
            #The info value should be chosen to be distinct from other uses of HKDF in the application.
            info=None
            )
        result = kdf.derive(dh_out)
        return (result[:32], result[32:])
        
    def KDF_CK(self, ck) -> (bytes, bytes):
        """Returns a pair (32-byte chain key, 32-byte message key)
as the output of applying a KDF keyed by a 32-byte chain key ck to some
constant."""
        #FIXME
        #fixed values for testing purposes (not allowed in final version)
        return (b'00000000000000000000000000000000', b'00000000000000000000000000000000')
        ...
    
    def ENCRYPT(self, mk, plaintext, associated_data):
        """Returns an AEAD
encryption of plaintext with message key mk [5]. The associated_data is
authenticated but is not included in the ciphertext. Because each message
key is only used once, the AEAD nonce may handled in several ways: fixed
to a constant; derived from mk alongside an independent AEAD encryption
key; derived as an additional output from KDF_CK(); or chosen randomly
and transmitted."""
        ...
        
    def DECRYPT(self, mk, ciphertext, associated_data):
        """ Returns the AEAD
decryption of ciphertext with message key mk. If authentication fails, an
exception will be raised that terminates processing."""
        ...
        
    def HEADER(self, dh_pair, pn, n):
        """Creates a new message header containing
the DH ratchet public key from the key pair in dh_pair, the previous chain
length pn, and the message number n. The returned header object contains
ratchet public key dh and integers pn and n."""
        ...
    
    def CONCAT(self, ad, header):
        """Encodes a message header into a parseable byte
sequence, prepends the ad byte sequence, and returns the result. If ad is
not guaranteed to be a parseable byte sequence, a length value should be
prepended to the output to ensure that the output is parseable as a unique
pair (ad, header)."""
        ...
    
    def RatchetInitAlice(self, state: State, SK, bob_dh_public_key):
        state.DHs = self.GENERATE_DH()
        state.DHr = bob_dh_public_key
        state.RK, state.CKs = self.KDF_RK(SK, self.DH(state.DHs, state.DHr))
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}
        
    def RatchetInitBob(self, state: State, SK, bob_dh_key_pair):
        state.DHs = bob_dh_key_pair
        state.DHr = None
        state.RK = SK
        state.CKs = None
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}

    def DHRatchet(self, state: State, header):
        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0
        state.DHr = header.dh
        state.RK, state.CKr = self.KDF_RK(state.RK, self.DH(state.DHs, state.DHr))
        state.DHs = self.GENERATE_DH()
        state.RK, state.CKs = self.KDF_RK(state.RK, self.DH(state.DHs, state.DHr))

    def RatchetEncrypt(self, state: State, plaintext, AD):
        self.state.CKs, mk = self.KDF_CK(state.CKs)
        header = self.HEADER(state.DHs, state.PN, state.Ns)
        state.Ns += 1
        return header, self.ENCRYPT(mk, plaintext, self.CONCAT(AD, header))

    def RatchetDecrypt(self, state: State, header, ciphertext, AD):
        plaintext = self.TrySkippedMessageKeys(state, header, ciphertext, AD)
        if plaintext != None:
            return plaintext
        if header.dh != state.DHr:
            self.SkipMessageKeys(state, header.pn)
            self.DHRatchet(state, header)
            self.SkipMessageKeys(state, header.n)
            state.CKr, mk = self.KDF_CK(state.CKr)
            state.Nr += 1
        return self.DECRYPT(mk, ciphertext, self.CONCAT(AD, header))

    def TrySkippedMessageKeys(self, state: State, header, ciphertext, AD):
        if (header.dh, header.n) in state.MKSKIPPED:
            mk = state.MKSKIPPED[header.dh, header.n]
            del state.MKSKIPPED[header.dh, header.n]
            return self.DECRYPT(mk, ciphertext, self.CONCAT(AD, header))
        else:
            return None
        
    def SkipMessageKeys(self, state: State, until):
        if state.Nr + self.MAX_SKIP < until:
            raise Error()
        if state.CKr != None:
            while state.Nr < until:
                state.CKr, mk = self.KDF_CK(state.CKr)
                state.MKSKIPPED[state.DHr, state.Nr] = mk
                state.Nr += 1



#constant_time.bytes_eq(b"foo", b"foo")

def isEqual(key1: bytes, key2: bytes) -> bool:
    constant_time.bytes_eq(key1, key2)
    
if __name__ == "__main__":
    
    doubleRatchet = DoubleRatchet()
    DhKeys = doubleRatchet.GENERATE_DH()
    
    state = State()
    
    
    
    print(DhKeys)
    