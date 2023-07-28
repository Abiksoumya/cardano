from __future__ import annotations
import json
import os
from typing import Optional, Type
from .serialization import CBORSerializable,limit_primitive_type
from .exception import InvalidKeyTypeException
from nacl.signing import SigningKey as NACLSigningKey
from .hash import VerificationKeyHash,VERIFICATION_KEY_HASH_SIZE
from nacl.public import PrivateKey
from nacl.encoding import RawEncoder
from nacl.hash import blake2b
from .crypto.bip32 import BIP32ED25519PrivateKey





__all__ = [
    "Key",
    "ExtendedSigningKey",
    "ExtendedVerificationKey",
    "VerificationKey",
    "SigningKey",
    "PaymentExtendedSigningKey",
    "PaymentExtendedVerificationKey",
    "PaymentSigningKey",
    "PaymentVerificationKey",
    
]



class Key(CBORSerializable):
    """A class that holds a cryptographic key and some metadata. e.g. signing key, verification key."""

    KEY_TYPE = ""
    DESCRIPTION = ""

    def __init__(
        self,
        payload: bytes,
        key_type: Optional[str] = None,
        description: Optional[str] = None,
    ):
        self._payload = payload
        self._key_type = key_type or self.KEY_TYPE
        self._description = description or self.KEY_TYPE

    @property
    def payload(self) -> bytes:
        return self._payload

    @property
    def key_type(self) -> str:
        return self._key_type

    @property
    def description(self) -> str:
        return self._description

    def to_primitive(self) -> bytes:
        return self.payload
    
    @classmethod
    @limit_primitive_type(bytes)
    def from_primitive(cls: Type["Key"], value: bytes) -> Key:
        return cls(value)
    
    def to_json(self) -> str:
        """Serialize the key to JSON.

        The json output has three fields: "type", "description", and "cborHex".

        Returns:
            str: JSON representation of the key.
        """
        return json.dumps(
            {
                "type": self.key_type,
                "description": self.description,
                "cborHex": self.to_cbor_hex(),
            }
        )
    
    @classmethod
    def from_json(cls: Type[Key], data: str, validate_type=False) -> Key:
        """Restore a key from a JSON string.

        Args:
            data (str): JSON string.
            validate_type (bool): Checks whether the type specified in json object is the same
                as the class's default type.

        Returns:
            Key: The key restored from JSON.

        Raises:
            InvalidKeyTypeException: When `validate_type=True` and the type in json is not equal to the default type
                of the Key class used.
        """
        obj = json.loads(data)

        if validate_type and obj["type"] != cls.KEY_TYPE:
            raise InvalidKeyTypeException(
                f"Expect key type: {cls.KEY_TYPE}, got {obj['type']} instead."
            )

        k = cls.from_cbor(obj["cborHex"])

        assert isinstance(k, cls)

        return cls(
            k.payload,
            key_type=obj["type"],
            description=obj["description"],
        )
    
    def save(self, path: str):
        if os.path.isfile(path):
            if os.stat(path).st_size > 0:
                raise IOError(f"File {path} already exists!")
        with open(path, "w") as f:
            f.write(self.to_json())

    @classmethod
    def load(cls, path: str):
        with open(path) as f:
            return cls.from_json(f.read())

    def __bytes__(self):
        return self.payload
    
    def __eq__(self, other):
        if not isinstance(other, Key):
            return False
        else:
            return (
                self.payload == other.payload
                and self.description == other.description
                and self.key_type == other.key_type
            )
        
    def __repr__(self) -> str:
        return self.to_json()

    def __hash__(self):
        return hash(self.payload)
    
class VerificationKey(Key):
    def hash(self) -> VerificationKeyHash:
        """Compute a blake2b hash from the key

        Returns:
            VerificationKeyHash: Hash output in bytes.
        """

        return VerificationKeyHash(
                blake2b(self.payload, VERIFICATION_KEY_HASH_SIZE, encoder=RawEncoder)
            )

    @classmethod
    def from_signing_key(cls, key: SigningKey) -> VerificationKey:
        return key.to_verification_key()
    
class ExtendedVerificationKey(Key):
    def hash(self) -> VerificationKeyHash:
        """Compute a blake2b hash from the key, excluding chain code

        Returns:
            VerificationKeyHash: Hash output in bytes.
        """
        return self.to_non_extended().hash()
    
    @classmethod
    def from_signing_key(cls, key: ExtendedSigningKey) -> ExtendedVerificationKey:
        return key.to_verification_key()

    def to_non_extended(self) -> VerificationKey:
        """Get the 32-byte verification with chain code trimmed off

        Returns:
            VerificationKey: 32-byte verification with chain code trimmed off
        """
        return VerificationKey(self.payload[:32])

    
class ExtendedSigningKey(Key):
    def sign(self, data: bytes) -> bytes:
        private_key = BIP32ED25519PrivateKey(self.payload[:64], self.payload[96:])
        return private_key.sign(data)
    
    def to_verification_key(self) -> ExtendedVerificationKey:
        return ExtendedVerificationKey(
            self.payload[64:],
            self.key_type.replace("Signing", "Verification"),
            self.description.replace("Signing", "Verification"),
        )

    
class SigningKey(Key):
    def sign(self, data: bytes) -> bytes:
        signed_message = NACLSigningKey(self.payload).sign(data)
        return signed_message.signature
    
    def to_verification_key(self) -> VerificationKey:
        verification_key = NACLSigningKey(self.payload).verify_key
        return VerificationKey(
            bytes(verification_key),
            self.key_type.replace("Signing", "Verification"),
            self.description.replace("Signing", "Verification"),
        )

    @classmethod
    def generate(cls) -> SigningKey:
        signing_key = PrivateKey.generate()
        return cls(bytes(signing_key))


class PaymentSigningKey(SigningKey):
    KEY_TYPE = "PaymentSigningKeyShelley_ed25519"
    DESCRIPTION = "Payment Signing Key"


class PaymentVerificationKey(VerificationKey):
    KEY_TYPE = "PaymentVerificationKeyShelley_ed25519"
    DESCRIPTION = "Payment Verification Key"


class PaymentExtendedSigningKey(ExtendedSigningKey):
    KEY_TYPE = "PaymentExtendedSigningKeyShelley_ed25519_bip32"
    DESCRIPTION = "Payment Signing Key"

class PaymentExtendedVerificationKey(ExtendedVerificationKey):
    KEY_TYPE = "PaymentExtendedVerificationKeyShelley_ed25519_bip32"
    DESCRIPTION = "Payment Verification Key"