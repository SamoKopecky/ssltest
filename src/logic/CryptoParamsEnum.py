from enum import Enum, auto


class CryptoParamsEnum(Enum):
    PROTOCOL = auto()
    PROTOCOL_VERSION = auto()
    KEY_EXCHANGE_ALG = auto()
    CERT_PUB_KEY_ALG = auto()
    CERT_PUB_KEY_LEN = auto()
    SYM_ENCRYPT_ALG = auto()
    SYM_ENCRYPT_ALG_KEY_LEN = auto()
    SYM_ENCRYPT_ALG_BLOCK_MODE = auto()
    SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER = auto()
    HASH_FUN = auto()
    CERT_SIG_ALG = auto()
    CERT_SIG_ALG_HASH_FUN = auto()
    HMAC = auto()

    @property
    def key_pair(self):
        pairs = {
            self.SYM_ENCRYPT_ALG_KEY_LEN: self.SYM_ENCRYPT_ALG,
            self.CERT_PUB_KEY_LEN: self.CERT_PUB_KEY_ALG,
            self.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER: self.SYM_ENCRYPT_ALG_BLOCK_MODE
        }
        return pairs[self]

    @property
    def alias(self):
        aliases = {
            self.PROTOCOL: 'Typ protokolu',
            self.PROTOCOL_VERSION: 'Verzia protokolu',
            self.KEY_EXCHANGE_ALG: 'Algoritmus výmenu kľúčov',
            self.CERT_PUB_KEY_ALG: 'Algoritmus verejného kľúča',
            self.CERT_PUB_KEY_LEN: 'Veľkosť verejného kľúča',
            self.SYM_ENCRYPT_ALG: 'Algoritmus symetrickej šifry',
            self.SYM_ENCRYPT_ALG_KEY_LEN: 'Veľkosť kĺúča symetrickej šifry',
            self.SYM_ENCRYPT_ALG_BLOCK_MODE: 'Blokový mód symetrickej šifry',
            self.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER: 'TODO',
            self.HASH_FUN: 'Hash funkcia',
            self.CERT_SIG_ALG: 'Algoritmus podpisu certifikátu',
            self.CERT_SIG_ALG_HASH_FUN: 'Hash funkcia pre popdis certifikátu',
            self.HMAC: 'TODO',
        }
        return aliases[self]

    @property
    def is_parsable(self):
        parsable = [self.KEY_EXCHANGE_ALG, self.SYM_ENCRYPT_ALG, self.SYM_ENCRYPT_ALG_KEY_LEN,
                    self.SYM_ENCRYPT_ALG_BLOCK_MODE, self.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER, self.HASH_FUN,
                    self.CERT_PUB_KEY_ALG, self.HMAC]
        return self in parsable
