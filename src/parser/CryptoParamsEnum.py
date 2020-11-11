from enum import Enum


class CryptoParamsEnum(Enum):
    KEY_EXCHANGE_ALG = 0 # Hranica od ktorej sa budu vyicitavat parametre zo cipher suite
    SYM_ENCRYPT_ALG = 1
    SYM_ENCRYPT_ALG_KEY_LEN = 2
    SYM_ENCRYPT_ALG_BLOCK_MODE = 3
    SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER = 4
    HASH_FUN = 5
    CERT_PUB_KEY_ALG_KEY_ALG = 6
    HMAC = 7 # Hranica do ktorej sa budu vyicitavat parametre zo cipher suite
    PROTOCOL = 8
    PROTOCOL_VERSION = 9
    CERT_SIG_ALG = 10
    CERT_SIG_ALG_HASH_FUN = 11
    CERT_PUB_KEY_ALG_KEY_LEN = 12

    def get_key_pair(self):
        pairs = {
            self.SYM_ENCRYPT_ALG_KEY_LEN: self.SYM_ENCRYPT_ALG,
            self.CERT_PUB_KEY_ALG_KEY_LEN: self.CERT_PUB_KEY_ALG_KEY_ALG,
            self.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER: self.SYM_ENCRYPT_ALG_BLOCK_MODE
        }
        return pairs[self]
