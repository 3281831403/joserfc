from unittest import TestCase

from joserfc import jwe
from joserfc.errors import (
    DecodeError,
    InvalidKeyIdError,
    InvalidKeyLengthError,
    InvalidKeyTypeError,
    UnsupportedAlgorithmError,
    UnsupportedHeaderError,
)
from joserfc.jwe import FlattenedJSONEncryption, GeneralJSONEncryption
from joserfc.jwk import KeySet, OctKey, RSAKey
from joserfc.registry import HeaderParameter
from tests.base import load_key


class TestJWEErrors(TestCase):
    def test_dir_with_invalid_key_type(self):
        key1 = load_key("ec-p256-private.pem")
        protected = {"alg": "dir", "enc": "A128CBC-HS256"}
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected,
            b"i",
            key1,
        )

        protected = {"alg": "A128KW", "enc": "A128CBC-HS256"}
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected,
            b"i",
            key1,
        )

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128CBC-HS256"}
        key2 = OctKey.import_key("secret")
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected,
            b"i",
            key2,
        )

        protected = {"alg": "PBES2-HS256+A128KW", "enc": "A128CBC-HS256"}
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected,
            b"i",
            key1,
            algorithms=["PBES2-HS256+A128KW", "A128CBC-HS256"],
        )

    def test_rsa_with_invalid_key_type(self):
        key = load_key("ec-p256-private.pem")
        protected = {"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected,
            b"i",
            key,
        )

    def test_A128KW_unwrap_error(self):
        key1 = OctKey.generate_key(128)
        key2 = OctKey.generate_key(128)
        protected = {"alg": "A128KW", "enc": "A128CBC-HS256"}
        value = jwe.encrypt_compact(protected, b"i", key1)
        self.assertRaises(DecodeError, jwe.decrypt_compact, value, key2)

    def test_unsupported_algorithm(self):
        key = OctKey.generate_key(128)
        protected = {"alg": "INVALID", "enc": "A128CBC-HS256"}
        self.assertRaises(UnsupportedAlgorithmError, jwe.encrypt_compact, protected, b"i", key)

        registry = jwe.JWERegistry(algorithms=["A128GCMKW"])
        self.assertRaises(UnsupportedAlgorithmError, jwe.encrypt_compact, protected, b"i", key, registry=registry)

    def test_invalid_key_length(self):
        protected = {"alg": "dir", "enc": "A128CBC-HS256"}
        key = OctKey.import_key("secret")
        self.assertRaises(InvalidKeyLengthError, jwe.encrypt_compact, protected, b"i", key)
        protected = {"alg": "A128KW", "enc": "A128CBC-HS256"}
        self.assertRaises(InvalidKeyLengthError, jwe.encrypt_compact, protected, b"i", key)
        protected = {"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}
        rsa_key = RSAKey.generate_key(1024)
        self.assertRaises(InvalidKeyLengthError, jwe.encrypt_compact, protected, b"i", rsa_key)

    def test_extra_header(self):
        key = OctKey.generate_key(256)
        protected = {"alg": "dir", "enc": "A128CBC-HS256", "custom": "hi"}
        self.assertRaises(UnsupportedHeaderError, jwe.encrypt_compact, protected, b"i", key)

        registry = jwe.JWERegistry(strict_check_header=False)
        jwe.encrypt_compact(protected, b"i", key, registry=registry)

        registry = jwe.JWERegistry(header_registry={"custom": HeaderParameter("Custom", "str")})
        jwe.encrypt_compact(protected, b"i", key, registry=registry)

    def test_strict_check_header_with_more_header_registry(self):
        key = load_key("ec-p256-private.pem")
        protected = {"alg": "ECDH-ES", "enc": "A128CBC-HS256", "custom": "hi"}
        self.assertRaises(UnsupportedHeaderError, jwe.encrypt_compact, protected, b"i", key)
        registry = jwe.JWERegistry(strict_check_header=False)
        jwe.encrypt_compact(protected, b"i", key, registry=registry)

    def test_empty_algorithms_deny_all(self):
        """An empty algorithm collection must reject every JWE entry point."""
        key = OctKey.generate_key(128)
        protected = {"alg": "A128KW", "enc": "A128CBC-HS256"}
        value = jwe.encrypt_compact(protected, b"i", key)

        for empty in ([], set(), ()):
            self.assertRaises(
                UnsupportedAlgorithmError,
                jwe.encrypt_compact,
                protected,
                b"i",
                key,
                algorithms=empty,
            )
            self.assertRaises(
                UnsupportedAlgorithmError,
                jwe.decrypt_compact,
                value,
                key,
                algorithms=empty,
            )

        # an explicitly constructed registry with an empty allow-list
        registry = jwe.JWERegistry(algorithms=[])
        self.assertRaises(
            UnsupportedAlgorithmError,
            jwe.decrypt_compact,
            value,
            key,
            registry=registry,
        )

        # JSON serialization, flattened and general forms
        flattened = FlattenedJSONEncryption(protected, b"i")
        flattened.add_recipient({}, key)
        flattened_value = jwe.encrypt_json(flattened, None)
        self.assertRaises(
            UnsupportedAlgorithmError,
            jwe.decrypt_json,
            flattened_value,
            key,
            algorithms=[],
        )

        general = GeneralJSONEncryption(protected, b"i")
        general.add_recipient({}, key)
        general_value = jwe.encrypt_json(general, None)
        self.assertRaises(
            UnsupportedAlgorithmError,
            jwe.decrypt_json,
            general_value,
            key,
            algorithms=[],
        )

    def test_algorithm_checked_before_key_lookup_compact(self):
        """Decrypt must validate the algorithm before looking up the key,
        so an allow-list violation surfaces as UnsupportedAlgorithmError
        instead of leaking a kid lookup failure."""
        key = OctKey.generate_key(128, {"kid": "known"})
        other = OctKey.generate_key(128, {"kid": "other"})
        key_set = KeySet([other])
        protected = {"alg": "A128KW", "enc": "A128CBC-HS256", "kid": "known"}
        value = jwe.encrypt_compact(protected, b"i", key)

        # the kid is absent from the KeySet, which would normally raise
        # InvalidKeyIdError; the empty allow-list must win instead
        with self.assertRaises(UnsupportedAlgorithmError):
            jwe.decrypt_compact(value, key_set, algorithms=[])

        # sanity check: the kid lookup failure itself still occurs without
        # the algorithm restriction
        with self.assertRaises(InvalidKeyIdError):
            jwe.decrypt_compact(value, key_set)

        # the same ordering applies to encryption
        with self.assertRaises(UnsupportedAlgorithmError):
            jwe.encrypt_compact(protected, b"i", key_set, algorithms=[])

        with self.assertRaises(InvalidKeyIdError):
            jwe.encrypt_compact(protected, b"i", key_set)

    def test_algorithm_checked_before_key_lookup_json(self):
        """Same ordering guarantee for the JWE JSON decryption path."""
        key = OctKey.generate_key(128, {"kid": "known"})
        other = OctKey.generate_key(128, {"kid": "other"})
        key_set = KeySet([other])
        protected = {"alg": "A128KW", "enc": "A128CBC-HS256"}
        obj = FlattenedJSONEncryption(protected, b"i")
        obj.add_recipient({"kid": "known"}, key)
        value = jwe.encrypt_json(obj, None)

        with self.assertRaises(UnsupportedAlgorithmError):
            jwe.decrypt_json(value, key_set, algorithms=[])

        with self.assertRaises(InvalidKeyIdError):
            jwe.decrypt_json(value, key_set)

        # and for JSON encryption
        encrypt_obj = FlattenedJSONEncryption(protected, b"i")
        encrypt_obj.add_recipient({"kid": "known"})
        with self.assertRaises(UnsupportedAlgorithmError):
            jwe.encrypt_json(encrypt_obj, key_set, algorithms=[])

        with self.assertRaises(InvalidKeyIdError):
            jwe.encrypt_json(encrypt_obj, key_set)
