"""
Script for decrypting encrypted apple disk images.

(c) 2019 Willem Hengeveld <itsme@xs4all.nl>
"""

from __future__ import annotations

import io
import struct
import logging
import argparse
from binascii import a2b_hex, b2a_hex
from typing import TYPE_CHECKING, BinaryIO, ClassVar

import Cryptodome.Hash.HMAC
import Cryptodome.Protocol.KDF
import Cryptodome.PublicKey.RSA
import Cryptodome.Cipher.PKCS1_v1_5
from Cryptodome.Cipher import AES, DES3

try:
    import Cryptodome.Hash.SHA1 as SHA1
except ImportError:
    import Cryptodome.Hash.SHA as SHA1

if TYPE_CHECKING:
    from Cryptodome.PublicKey.RSA import RsaKey

logger = logging.getLogger(__name__)


def hexdump(data: bytes) -> None:
    """
    Prints a hexdump of 'data' to stdout, 16 bytes per line.
    """
    for o in range(0, len(data), 16):
        line = f"{o:04x}:"
        for i in range(16):
            if o + i < len(data):
                line += f" {data[o + i]:02x}"
            else:
                line += "   "
        line += "  "
        for i in range(16):
            if o + i < len(data):
                line += chr(data[o + i]) if 32 <= data[o + i] <= 126 else "."
            else:
                line += " "
        logger.debug(line)


def hmacsha1(key: bytes, data: bytes) -> bytes:
    """
    calculates a sha1-hmac. ( see rfc2104 )
    """
    hm = Cryptodome.Hash.HMAC.new(key, digestmod=SHA1)
    hm.update(data)
    return hm.digest()


def pbkdf2(data: bytes, nonce: bytes, itercount: int) -> bytes:
    """
    Password Based Key Derivation Function # 2 - see rfc2898
    """
    return Cryptodome.Protocol.KDF.PBKDF2(data, nonce, 32, itercount, prf=hmacsha1)  # type: ignore[arg-type]


def remove_pkcs7_padding(data: bytes, blocksize: int) -> bytes:
    """
    PKCS7 - Symmetric cipher padding
    """
    padlen = ord(data[-1:])
    if padlen == 0 or padlen > blocksize:
        raise Exception("invalid padding")

    for i in range(padlen):
        if data[-1 - i] != data[-1]:
            logger.warning(f"invalid padding: {b2a_hex(data[-padlen:])}")
            raise Exception("invalid padding")
    return data[:-padlen]


class Struct:
    fieldinfo: ClassVar[list[tuple]] = []

    def __init__(self, *args) -> None:
        if len(args) == 1 and isinstance(args[0], bytes):
            self.parse(args[0])

    def parse(self, data: bytes) -> None:
        pass

    def dumplist(self, o: int, k: str, v: list) -> None:
        if not v:
            logger.debug(f"{o:04x}: {k:<40} []")
        elif isinstance(v[0], int):
            vals = ", ".join(f"0x{_:08x}" for _ in v)
            logger.debug(f"{o:04x}: {k:<40} [{vals}]")
        elif isinstance(v[0], Struct):
            for item in v:
                item.dump()
        else:
            logger.debug(f"{o:04x}: {k:<40} {v}")

    def dumpval(self, o: int, k: str, v: int | bytes | list | Struct) -> None:
        if isinstance(v, Struct):
            v.dump()
        elif isinstance(v, bytes):
            logger.debug(f"{o:04x}: {k:<40} {b2a_hex(v)}")
        elif isinstance(v, int):
            logger.debug(f"{o:04x}: {k:<40} 0x{v:08x}")
        elif isinstance(v, list):
            self.dumplist(o, k, v)
        else:
            logger.debug(f"{o:04x}: {k:<40}: {v}")

    def dump(self) -> None:
        if hasattr(self, "header"):
            self.header.dump()  # type: ignore[attr-defined]
        logger.debug(f"====== {self.__class__.__name__} ====== <<")
        for o, aname, _atype in self.fieldinfo:
            val = getattr(self, aname)
            self.dumpval(o, aname, val)
        logger.debug(">>")


CSSM_ALGID_PKCS5_PBKDF2 = 0x67
CSSM_ALGID_3DES_3KEY_EDE = 0x11
CSSM_PADDING_PKCS7 = 7
CSSM_ALGMODE_CBCPadIV8 = 6

CSSM_APPLE_UNLOCK_TYPE_KEY_DIRECT = 1  # master secret key stored directly
CSSM_APPLE_UNLOCK_TYPE_WRAPPED_PRIVATE = 2  # master key wrapped by public key
CSSM_APPLE_UNLOCK_TYPE_KEYBAG = 3  # master key wrapped via keybag


class PassphraseWrappedKey(Struct):
    """
    A encrcdsa v2 password wrapped key.
    """

    fieldinfo: ClassVar[list[tuple]] = [
        (0x0000, "kdfAlgorithm", "L"),  # 0x67  CSSM_ALGID_PKCS5_PBKDF2
        (0x0004, "kdfIterationCount", "Q"),  # between 0x10000 and 0x50000
        (0x000C, "kdfSaltLen", "L"),  # in bytes - 20
        (0x0010, "kdfSalt", "32s"),
        (0x0030, "blobEncIvLen", "L"),  # in bytes - 8
        (0x0034, "blobEncIv", "32s"),
        (0x0054, "blobEncKeyBits", "L"),  # in bits - 192
        (0x0058, "blobEncAlgorithm", "L"),  # 0x11 CSSM_ALGID_3DES_3KEY_EDE
        (0x005C, "blobEncPadding", "L"),  # 0x07 CSSM_PADDING_PKCS7
        (0x0060, "blobEncMode", "L"),  # 0x06 CSSM_ALGMODE_CBCPadIV8
        (0x0064, "encryptedKeyblobLen", "L"),  # in bytes 48 or 64
        (0x0068, "encryptedKeyblob", "64s"),
    ]

    def parse(self, data: bytes) -> None:
        (
            self.kdfAlgorithm,  # CSSM_ALGID_PKCS5_PBKDF2
            self.kdfIterationCount,
            self.kdfSaltLen,  # 0x14
            self.kdfSalt,  # ...
            self.blobEncIvLen,  # 8
            self.blobEncIv,  # ...
            self.blobEncKeyBits,  # 0xc0 (bits)  = 24 bytes
            self.blobEncAlgorithm,  #  CSSM_ALGID_3DES_3KEY_EDE
            self.blobEncPadding,  #  CSSM_PADDING_PKCS7
            self.blobEncMode,  #  CSSM_ALGMODE_CBCPadIV8
            self.encryptedKeyblobLen,  # 0x30, or 0x40   in bytes
        ) = struct.unpack(">LQL32sL32s5L", data[:0x68])
        self.encryptedKeyblob = data[0x68:]

    def isvalid(self) -> bool:
        """
        Check if we can decode this wrapped key.
        """
        if self.kdfAlgorithm != CSSM_ALGID_PKCS5_PBKDF2:
            logger.error(f"unsupported kdf algorithm: {self.kdfAlgorithm}")
        elif self.blobEncAlgorithm != CSSM_ALGID_3DES_3KEY_EDE:
            logger.error(f"unsupported wrap algorithm: {self.blobEncAlgorithm}")
        elif self.blobEncPadding != CSSM_PADDING_PKCS7:
            logger.error(f"unsupported wrap padding: {self.blobEncPadding}")
        elif self.blobEncMode != CSSM_ALGMODE_CBCPadIV8:
            logger.error(f"unsupported wrap encmode: {self.blobEncMode}")
        else:
            return True
        return False

    def unwrapkey(self, passphrase: bytes, *, skipkdf: bool = False) -> bytes:
        """
        decrypt the key using a passphrase.
        """
        if not skipkdf:
            hashedpw = pbkdf2(passphrase, self.kdfSalt[: self.kdfSaltLen], self.kdfIterationCount)
            logger.debug(f"hashedpw = {b2a_hex(hashedpw)}")
            deskey = hashedpw[: self.blobEncKeyBits // 8]
            iv = self.blobEncIv[: self.blobEncIvLen]
        else:
            deskey = passphrase[: self.blobEncKeyBits // 8]
            iv = passphrase[self.blobEncKeyBits // 8 :]

        des = DES3.new(deskey, mode=DES3.MODE_CBC, IV=iv)
        unwrappeddata = des.decrypt(self.encryptedKeyblob[: self.encryptedKeyblobLen])
        logger.debug(f"deskey = {b2a_hex(deskey)}")
        logger.debug(f"iv = {b2a_hex(iv)}")
        logger.debug(f"unwrappeddata = {b2a_hex(unwrappeddata)}")
        keydata = remove_pkcs7_padding(unwrappeddata, self.blobEncIvLen)
        logger.debug(f"keydata = {b2a_hex(keydata)}")

        if keydata[-5:] != b"CKIE\x00":
            logger.error(f"v2 unwrap: missing CKIE suffix: {b2a_hex(keydata[-5:])}")

        return keydata[:-5]


class CertificateWrappedKey(Struct):
    """
    A encrcdsa v2 cert wrapped key.
    """

    fieldinfo: ClassVar[list[tuple]] = [
        (0x0000, "pubkeyHashLength", "L"),  # 0x14
        (0x0004, "pubkeyHash", "20s"),
        (0x0018, "unk1", "L"),  # 0
        (0x001C, "unk2", "L"),  # 0
        (0x0020, "unk3", "L"),  # 0
        (0x0024, "alg1", "L"),  # 42 == RSA
        (0x0028, "unk4", "L"),  # 10
        (0x002C, "unk5", "L"),  # 0
        (0x0030, "unk6", "L"),  # 0x100
        (0x0068, "wrappedKey", "256s"),
    ]

    def parse(self, data: bytes) -> None:
        (
            self.pubkeyHashLength,  # 0x14
            self.pubkeyHash,
            self.unk1,
            self.unk2,
            self.unk3,
            self.alg1,
            self.unk4,
            self.unk5,
            self.unk6,
            self.wrappedKey,
        ) = struct.unpack(">L20s7L256s", data[:0x134])

    def isvalid(self) -> bool:
        """
        Check if we can decode this wrapped key.
        """
        if self.pubkeyHashLength != 20:
            logger.error(f"unsupported cert hash size: {self.pubkeyHashLength}")
        elif self.alg1 != 42:
            logger.error(f"unsupported wrap algorithm: {self.alg1}")
        else:
            return True
        return False

    def unwrapkey(self, privkey: RsaKey, **_kwargs) -> bytes:
        """
        decrypt the key using a private key
        """
        cipher = Cryptodome.Cipher.PKCS1_v1_5.new(privkey)
        keydata = cipher.decrypt(self.wrappedKey, b"xxxxx")

        if keydata[-5:] != b"CKIE\x00":
            logger.error(f"v2 unwrap: missing CKIE suffix: {b2a_hex(keydata[-5:])}")

        return keydata[:-5]


class BaggedKey(Struct):
    """
    A encrcdsa v2 key-bag

    TODO - figure out how this works
    """

    fieldinfo: ClassVar[list[tuple]] = [
        (0x0000, "keybag", "128s"),
    ]

    def __init__(self, data: bytes) -> None:
        self.keybag = data

    def isvalid(self) -> bool:
        """
        Check if we can decode this wrapped key.
        """
        return True

    def unwrapkey(self, _privkey: RsaKey, **_kwargs) -> None:
        """
        decrypt the key using a private key
        """
        return None


CSSM_ALGMODE_CBC_IV8 = 5
CSSM_ALGID_AES = 0x80000001
CSSM_ALGID_SHA1HMAC = 0x5B


class EncrCdsaFile(Struct):
    """
    Interface to a encrcdsa v2 file.
    """

    fieldinfo: ClassVar[list[tuple]] = [
        (0x0000, "signature", "8s"),
        (0x0008, "version", "L"),  # 2
        (0x000C, "blockIvLen", "L"),  # 16
        (0x0010, "blockMode", "L"),  # 5  CSSM_ALGMODE_CBC_IV8
        (0x0014, "blockAlgorithm", "L"),  # 0x80000001  CSSM_ALGID_AES
        (0x0018, "keyBits", "L"),  # in bits - 128 or 256
        (0x001C, "ivkeyAlgorithm", "L"),  # 0x5b CSSM_ALGID_SHA1HMAC
        (0x0020, "ivkeyBits", "L"),  # 160
        (0x0024, "unknownGuid", "16s"),
        (0x0034, "bytesPerBlock", "L"),  # 0x200
        (0x0038, "dataLen", "Q"),  # ... a little less than the total nr of bytes
        (0x0040, "offsetToDataStart", "Q"),  # 0x01de00
        (0x0048, "nritems", "L"),  # 1
        (0x004C, "keyitems", "*"),  # list of 20 byte records
        (0xFFFF, "wrappedkeys", "*"),  # decoded key items
    ]

    @staticmethod
    def hasmagic(fh: BinaryIO) -> bool:
        fh.seek(0, io.SEEK_SET)
        cdsatag = fh.read(12)
        if not cdsatag:
            return False
        (
            signature,
            version,
        ) = struct.unpack(">8sL", cdsatag)

        return signature == b"encrcdsa" and version == 2

    def nrblocks(self) -> int:
        return (self.dataLen - 1) // self.bytesPerBlock + 1

    def parse(self, data: bytes) -> None:
        (
            self.signature,  # "encrcdsa"
            self.version,  #  2
            self.blockIvLen,  # 16
            self.blockMode,  #  5   CSSM_ALGMODE_CBC_IV8
            self.blockAlgorithm,  # 0x80000001  CSSM_ALGID_AES
            self.keyBits,  # in bits   128  = 16 bytes
            self.ivkeyAlgorithm,  # CSSM_ALGID_SHA1HMAC
            self.ivkeyBits,  # in bits   160  = 20 bytes
            self.unknownGuid,
            self.bytesPerBlock,  # in bytes  0x200
            self.dataLen,  # in bytes
            self.offsetToDataStart,  # in bytes  0x01de00
            self.nritems,  # 1
        ) = struct.unpack(">8s7L16sLQQL", data[:0x4C])

        if self.signature != b"encrcdsa":
            raise Exception("not a encrcdsa header")

        o = 0x4C

        self.keyitems = []
        for _i in range(self.nritems):
            itemtype, itemoffset, itemsize = struct.unpack(">LQQ", data[o : o + 0x14])
            o += 0x14

            self.keyitems.append((itemtype, itemoffset, itemsize))

        self.wrappedkeys = []

        for tp, of, sz in self.keyitems:
            if tp == CSSM_APPLE_UNLOCK_TYPE_KEY_DIRECT:
                self.wrappedkeys.append(PassphraseWrappedKey(data[of : of + sz]))
            elif tp == CSSM_APPLE_UNLOCK_TYPE_WRAPPED_PRIVATE:
                self.wrappedkeys.append(CertificateWrappedKey(data[of : of + sz]))
            elif tp == CSSM_APPLE_UNLOCK_TYPE_KEYBAG:
                self.wrappedkeys.append(BaggedKey(data[of : of + sz]))

    def load(self, fh: BinaryIO) -> None:
        fh.seek(0, io.SEEK_SET)
        hdr = fh.read(0x10000)
        self.parse(hdr)

    def isvalid(self) -> bool:
        """
        Checks if we can decrypt this file.
        """
        if self.blockMode != CSSM_ALGMODE_CBC_IV8:
            logger.error(f"unsupported block mode: {self.blockMode}")
        elif self.blockAlgorithm != CSSM_ALGID_AES:
            logger.error(f"unsupported block algorithm: {self.blockAlgorithm}")
        elif self.ivkeyAlgorithm != CSSM_ALGID_SHA1HMAC:
            logger.error(f"unsupported ivkey algorithm: {self.ivkeyAlgorithm}")
        else:
            return True
        return False

    def login(self, passphrase: bytes | RsaKey, *, skipkdf: bool = False) -> bool:
        """
        Authenticate v2
        """
        for i, wp in enumerate(self.wrappedkeys):
            if not wp.isvalid():
                logger.error(f"key#{i} - {type(wp)} is not valid")
                continue
            try:
                keydata = wp.unwrapkey(passphrase, skipkdf=skipkdf)
                if keydata:
                    logger.debug(f"keydata = {b2a_hex(keydata)}")
                    self.setkey(keydata)
                    logger.info(f"FOUND: passphrase decodes wrappedkey #{i}")
                    return True
            except Exception:
                pass
        return False

    def setkey(self, keydata: bytes) -> None:
        self.aeskey = keydata[: self.keyBits // 8]
        self.hmackey = keydata[self.keyBits // 8 :]

    def readblock(self, fh: BinaryIO, blocknum: int) -> bytes:
        """
        Read and decrypt a single block
        """
        fh.seek(self.offsetToDataStart + blocknum * self.bytesPerBlock)
        data = fh.read(self.bytesPerBlock)

        # because: self.ivkeyAlgorithm == CSSM_ALGID_SHA1HMAC
        # sha1 implying: self.ivkeyBits == 160
        iv = hmacsha1(self.hmackey, struct.pack(">L", blocknum))

        # because: self.blockAlgorithm == CSSM_ALGID_AES
        # because: self.blockMode == CSSM_ALGMODE_CBC_IV8
        logger.debug(
            f"blk ofs: {self.offsetToDataStart + blocknum * self.bytesPerBlock:x}, iv={b2a_hex(iv)}"
        )
        aes = AES.new(self.aeskey, mode=AES.MODE_CBC, IV=iv[: self.blockIvLen])

        data = aes.decrypt(data)
        if blocknum == self.nrblocks() - 1:
            trunk = self.dataLen % self.bytesPerBlock
            return data[:trunk]
        return data


class CdsaEncrFile(Struct):
    """
    Interface to a cdsaencr v1 file.
    """

    fieldinfo: ClassVar[list[tuple]] = [
        (0x0000, "unknownGuid", "16s"),  #
        (0x0010, "bytesPerBlock", "L"),  #
        (0x0014, "blobEncAlgorithm", "L"),  # CSSM_ALGID_3DES_3KEY_EDE
        (0x0018, "blobEncPadding", "L"),  # CSSM_PADDING_PKCS7
        (0x001C, "blobEncMode", "L"),  # CSSM_ALGMODE_CBCPadIV8
        (0x0020, "blobEncKeyBits", "L"),  #
        (0x0024, "blobEncIvLen", "L"),  #
        (0x0028, "kdfAlgorithm", "L"),  # CSSM_ALGID_PKCS5_PBKDF2
        (0x002C, "kdfIterationCount", "Q"),  #   .. todo: should be L
        (0x0034, "kdfSaltLen", "L"),  #
        (0x0038, "kdfSalt", "32s"),  #
        (0x0058, "blockIvLen", "L"),  #
        (0x005C, "blockMode", "L"),  # CSSM_ALGMODE_CBC_IV8
        (0x0060, "blockAlgorithm", "L"),  # CSSM_ALGID_AES
        (0x0064, "keyBits", "L"),  #
        (0x0068, "keyIv", "32s"),  #
        (0x0088, "wrappedAesKeyLen", "L"),  #
        (0x008C, "wrappedAesKey", "256s"),  #
        (0x018C, "hmacAlgorithm", "L"),  # CSSM_ALGID_SHA1HMAC
        (0x0190, "hmacBits", "L"),  #
        (0x0194, "hmacIv", "32s"),  #
        (0x01B4, "wrappedHmacKeyLen", "L"),  #
        (0x01B8, "wrappedHmacKey", "256s"),  #
        (0x02B8, "integrityAlgorithm", "L"),  # CSSM_ALGID_SHA1HMAC
        (0x02BC, "integrityBits", "L"),  #
        (0x02C0, "integrityIv", "32s"),  #
        (0x02E0, "wrappedIntegrityKeyLen", "L"),  #
        (0x02E4, "wrappedIntegrityKey", "256s"),  #
        (0x03E4, "unkLen", "L"),  #
        (0x03E8, "unkData", "256s"),  #
        (0x04E8, "offsetToHeader", "Q"),  #
        (0x04F0, "version", "L"),  #
        (0x04F4, "signature", "8s"),  #
    ]

    @staticmethod
    def hasmagic(fh: BinaryIO) -> bool:
        fh.seek(-12, io.SEEK_END)
        cdsatag = fh.read(12)
        if not cdsatag:
            return False
        version, signature = struct.unpack(">L8s", cdsatag)

        return signature == b"cdsaencr" and version == 1

    def nrblocks(self) -> int:
        return (self.offsetToHeader - 1) // self.bytesPerBlock + 1

    def load(self, fh: BinaryIO) -> None:
        self.offsetToDataStart = 0

        fh.seek(-20, io.SEEK_END)
        cdsatag = fh.read(20)
        if not cdsatag:
            raise Exception("no cdsatag")
        self.offsetToHeader, self.version, self.signature = struct.unpack(">QL8s", cdsatag)

        if self.signature != b"cdsaencr":
            raise Exception("no cdsatag")

        fh.seek(self.offsetToHeader, io.SEEK_SET)
        infohdr = fh.read(0x4E8)
        if not infohdr:
            raise Exception("no infohdr")
        self.parse(infohdr)

    def parse(self, data: bytes) -> None:
        (
            self.unknownGuid,
            self.bytesPerBlock,
            self.blobEncAlgorithm,
            self.blobEncPadding,
            self.blobEncMode,
            self.blobEncKeyBits,
            self.blobEncIvLen,
            self.kdfAlgorithm,
            self.kdfIterationCount,
            self.kdfSaltLen,
            self.kdfSalt,
            self.blockIvLen,
            self.blockMode,
        ) = struct.unpack(">16s L L L L L L L Q L 32s L L", data[:0x60])

        o = 0x60

        (
            self.blockAlgorithm,
            self.keyBits,
            self.keyIv,
            self.wrappedAesKeyLen,
            self.wrappedAesKey,
        ) = struct.unpack(">L L 32s L 256s", data[o : o + 0x12C])

        o += 0x12C

        (
            self.hmacAlgorithm,
            self.hmacBits,
            self.hmacIv,
            self.wrappedHmacKeyLen,
            self.wrappedHmacKey,
        ) = struct.unpack(">L L 32s L 256s", data[o : o + 0x12C])

        o += 0x12C

        (
            self.integrityAlgorithm,
            self.integrityBits,
            self.integrityIv,
            self.wrappedIntegrityKeyLen,
            self.wrappedIntegrityKey,
        ) = struct.unpack(">L L 32s L 256s", data[o : o + 0x12C])

        o += 0x12C

        (
            self.unkLen,
            self.unkData,
        ) = struct.unpack(">L 256s", data[o : o + 0x104])

    def isvalid(self) -> bool:
        """
        Check if this v1 header uses our supported algorithms.
        """
        if self.blobEncAlgorithm != CSSM_ALGID_3DES_3KEY_EDE:
            logger.error(f"unsupported blobEncAlgorithm: {self.blobEncAlgorithm}")
        elif self.blobEncPadding != CSSM_PADDING_PKCS7:
            logger.error(f"unsupported blobEncPadding: {self.blobEncPadding}")
        elif self.blobEncMode != CSSM_ALGMODE_CBCPadIV8:
            logger.error(f"unsupported blobEncMode: {self.blobEncMode}")
        elif self.kdfAlgorithm != CSSM_ALGID_PKCS5_PBKDF2:
            logger.error(f"unsupported kdfAlgorithm: {self.kdfAlgorithm}")
        elif self.blockMode != CSSM_ALGMODE_CBC_IV8:
            logger.error(f"unsupported blockMode: {self.blockMode}")
        elif self.blockAlgorithm != CSSM_ALGID_AES:
            logger.error(f"unsupported blockAlgorithm: {self.blockAlgorithm}")
        elif self.hmacAlgorithm != CSSM_ALGID_SHA1HMAC:
            logger.error(f"unsupported hmacAlgorithm: {self.hmacAlgorithm}")
        else:
            return True
        return False

    def get_hmac_key(self, passphrase: bytes, *, skipkdf: bool = False) -> bytes:
        """
        decodes the hmac key
        """
        return self.unwrapkey(
            passphrase, self.wrappedHmacKey[: self.wrappedHmacKeyLen], skipkdf=skipkdf
        )

    def get_integrity_key(self, passphrase: bytes, *, skipkdf: bool = False) -> bytes:
        """
        decodes the integrity key
        """
        return self.unwrapkey(
            passphrase, self.wrappedIntegrityKey[: self.wrappedIntegrityKeyLen], skipkdf=skipkdf
        )

    def get_aes_key(self, passphrase: bytes, *, skipkdf: bool = False) -> bytes:
        """
        decodes the aes key
        """
        return self.unwrapkey(
            passphrase, self.wrappedAesKey[: self.wrappedAesKeyLen], skipkdf=skipkdf
        )

    def unwrapkey(self, passphrase: bytes, blob: bytes, *, skipkdf: bool = False) -> bytes:
        """
        Unwraps the keys using the algorithm specified in rfc3217 or rfc3537
        """
        if not skipkdf:
            hashedpw = pbkdf2(passphrase, self.kdfSalt[: self.kdfSaltLen], self.kdfIterationCount)
            deskey = hashedpw[: self.blobEncKeyBits // 8]
        else:
            deskey = passphrase[: self.blobEncKeyBits // 8]

        tdes_iv = b"\x4a\xdd\xa2\x2c\x79\xe8\x21\x05"
        des1 = DES3.new(deskey, mode=DES3.MODE_CBC, IV=tdes_iv)
        key1 = remove_pkcs7_padding(des1.decrypt(blob), self.blobEncIvLen)

        # note: standard says: use first block for iv,
        # this is equivalent to using a zero IV, and ignoring the first
        # plaintext block
        des2 = DES3.new(deskey, mode=DES3.MODE_CBC, IV=b"\x00" * 8)
        keydata = remove_pkcs7_padding(des2.decrypt(key1[::-1]), self.blobEncIvLen)

        if keydata[8:12] != b"\x00" * 4:
            logger.warning(f"tdes key unwrap has non zero prefix: {b2a_hex(keydata[8:12])}")

        return keydata[12:]

    def login(self, passphrase: bytes, *, skipkdf: bool = False) -> bool:
        """
        Authenticate v1
        """
        self.aeskey = self.get_aes_key(passphrase, skipkdf=skipkdf)
        self.hmackey = self.get_hmac_key(passphrase, skipkdf=skipkdf)
        self.ikey = self.get_integrity_key(passphrase, skipkdf=skipkdf)

        logger.debug(f"login -> aes={b2a_hex(self.aeskey)}, hmac={b2a_hex(self.hmackey)}")

        return True

    def setkey(self, keydata: bytes) -> None:
        self.aeskey = keydata[: self.keyBits // 8]
        self.hmackey = keydata[self.keyBits // 8 :]
        self.ikey = b""

    def readblock(self, fh: BinaryIO, blocknum: int) -> bytes:
        """
        Read and decrypt a single block
        """
        fh.seek(self.offsetToDataStart + blocknum * self.bytesPerBlock)
        data = fh.read(self.bytesPerBlock)
        iv = hmacsha1(self.hmackey, struct.pack(">L", blocknum))
        aes = AES.new(self.aeskey, mode=AES.MODE_CBC, IV=iv[: self.blockIvLen])
        return aes.decrypt(data)


def unlockfile(args: argparse.Namespace, enc: EncrCdsaFile | CdsaEncrFile) -> bool:
    """
    unlock the encrypted diskimage in `enc`,
    """
    enc.dump()

    passphrase: bytes | None = None
    if args.password:
        passphrase = args.password.encode("utf-8")
    elif args.hexpassword:
        passphrase = a2b_hex(args.hexpassword.replace(" ", ""))

    privatekey: RsaKey | None = None
    if args.privatekey:
        with open(args.privatekey, "rb") as f:
            privatekey = Cryptodome.PublicKey.RSA.importKey(f.read())

    if passphrase is not None:
        return enc.login(passphrase, skipkdf=args.skipkdf)
    elif privatekey is not None:
        return enc.login(privatekey)  # type: ignore[arg-type]
    elif args.keydata:
        enc.setkey(a2b_hex(args.keydata))
        return True
    return False


def savedecrypted(enc: EncrCdsaFile | CdsaEncrFile, fh: BinaryIO, filename: str) -> None:
    """
    Write all decrypted blocks to `filename`.
    """
    with open(filename, "wb") as ofh:
        for bnum in range(enc.nrblocks()):
            data = enc.readblock(fh, bnum)
            ofh.write(data)


def dumpblocks(enc: EncrCdsaFile | CdsaEncrFile, fh: BinaryIO) -> None:
    """
    print all decrypted blocks as hexdump to stdout.
    """
    for bnum in range(enc.nrblocks()):
        logger.info(f"-- blk {bnum}")
        data = enc.readblock(fh, bnum)
        hexdump(data)


def createdecryptedfilename(filename: str) -> str:
    """
    Determine a filename to save the decrypted diskimage to.
    """
    i = filename.rfind(".")
    if i < 0:
        return filename + "-decrypted"
    return filename[:i] + "-decrypted" + filename[i:]


def processfile(args: argparse.Namespace, filename: str, fh: BinaryIO) -> None:
    """
    determines the diskimage type, unlocks it,
    then performs action requested from the commandline.
    """
    enc: EncrCdsaFile | CdsaEncrFile | None = None
    for cls in (EncrCdsaFile, CdsaEncrFile):
        try:
            if cls.hasmagic(fh):
                enc = cls()
                enc.load(fh)
        except Exception as e:
            logger.error(f"ERR {e}")
            if args.debug:
                raise
    if not enc:
        logger.error("Did not find an encrypted disk image")
        return
    if not unlockfile(args, enc):
        logger.error("unlock failed")
        return
    if args.save:
        savedecrypted(enc, fh, createdecryptedfilename(filename))
    elif args.dump:
        dumpblocks(enc, fh)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A tool for decrypting Apple encrypted disk images."
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose output")
    parser.add_argument("--debug", action="store_true", help="abort on exceptions")
    parser.add_argument("--password", "-p", type=str, help="ASCII password")
    parser.add_argument("--privatekey", "-k", type=str, help="path to private key")
    parser.add_argument("--hexpassword", "-P", type=str, help="hex-encoded password")
    parser.add_argument("--keydata", "-K", type=str, help="direct key data")
    parser.add_argument(
        "--skipkdf",
        "-n",
        action="store_true",
        help="skip passphrase hashing - useful for ipsw decryption",
    )
    parser.add_argument("--save", "-s", action="store_true", help="save decrypted image")
    parser.add_argument("--dump", "-d", action="store_true", help="hexdump decrypted image")
    parser.add_argument("files", nargs="*", type=str, help="files to process")

    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")

    for filename in args.files:
        try:
            logger.info(f"==> {filename} <==")
            with open(filename, "rb") as fh:
                processfile(args, filename, fh)
        except Exception as e:
            logger.error(f"EXCEPTION {e}")
            if args.debug:
                raise


if __name__ == "__main__":
    main()
