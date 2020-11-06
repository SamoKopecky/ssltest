from enum import Enum


class CryptoParamsEnum(Enum):
    KEY_EXCHANGE_ALG = 0
    CERT_SIG_ALG = 1
    SYM_ENCRYPT_ALG = 2
    SYM_ENCRYPT_ALG_KEY_LEN = 3
    SYM_ENCRYPT_ALG_BLOCK_MODE = 4
    SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER = 5
    HASH_FUN = 6
    HMAC = 7
    PROTOCOL = 8
    PROTOCOL_VERSION = 9
    CERT_SIG_ALG_HASH_FUN = 10
    CERT_SIG_ALG_KEY_LEN = 11

    def get_key_pair(self):
        pairs = {
            self.SYM_ENCRYPT_ALG_KEY_LEN: self.SYM_ENCRYPT_ALG,
            self.CERT_SIG_ALG_KEY_LEN: self.CERT_SIG_ALG,
            self.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER: self.SYM_ENCRYPT_ALG_BLOCK_MODE
        }
        return pairs[self]
