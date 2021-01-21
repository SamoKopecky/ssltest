from enum import Enum, auto


class CryptoParamsEnum(Enum):
    """
    Enum type class that defines parameter types for cipher suite and certificate parameters.
    """
    PROTOCOL = auto()
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
        """
        Defines the algorithm to which the algorithm length belongs to.

        :return: algorithm type
        """
        pairs = {
            self.SYM_ENCRYPT_ALG_KEY_LEN: self.SYM_ENCRYPT_ALG,
            self.CERT_PUB_KEY_LEN: self.CERT_PUB_KEY_ALG,
            self.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER: self.SYM_ENCRYPT_ALG_BLOCK_MODE
        }
        return pairs[self]

    @property
    def string_alias(self):
        """
        Defines a string alias of a specific parameter

        :return: string
        """
        aliases = {
            self.PROTOCOL: 'Typ a verzia protokolu',
            self.KEY_EXCHANGE_ALG: 'Algoritmus výmenu kľúčov',
            self.CERT_PUB_KEY_ALG: 'Algoritmus verejného kľúča',
            self.CERT_PUB_KEY_LEN: 'Veľkosť verejného kľúča',
            self.SYM_ENCRYPT_ALG: 'Algoritmus symetrickej šifry',
            self.SYM_ENCRYPT_ALG_KEY_LEN: 'Veľkosť kľúča symetrickej šifry',
            self.SYM_ENCRYPT_ALG_BLOCK_MODE: 'Blokový mód symetrickej šifry',
            self.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER: 'Dodatočná inoformácia k blokovému módu',
            self.HASH_FUN: 'Hash funkcia',
            self.CERT_SIG_ALG: 'Algoritmus podpisu certifikátu',
            self.CERT_SIG_ALG_HASH_FUN: 'Hash funkcia pre podpis certifikátu',
            self.HMAC: 'Hmac funkcia',
        }
        return aliases[self]

    @property
    def is_parsable(self):
        """
        Defines which parameters are parsable from a cipher suite

        :return: true if a parameter is parsable
        """
        parsable = [self.KEY_EXCHANGE_ALG, self.SYM_ENCRYPT_ALG, self.SYM_ENCRYPT_ALG_KEY_LEN,
                    self.SYM_ENCRYPT_ALG_BLOCK_MODE, self.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER, self.HASH_FUN,
                    self.CERT_PUB_KEY_ALG, self.HMAC]
        return self in parsable
