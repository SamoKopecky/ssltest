import os
from src.parser.CryptoParamsEnum import CryptoParamsEnum as CPEnum

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

FILE_NAMES = [
    'key_exchange_algorithm.txt',
    'certificate_signature_algorithm.txt',
    'symetric_encryption_algorithm.txt',
    'symetric_encryption_algorithm_key_length.txt',
    'symetric_encryption_algorithm_block_mode.txt',
    'symetric_encryption_algorithm_block_mode_number.txt',
    'cipher_suite_hash_function.txt',
    'hmac.txt'
]


class CryptoParams:
    security_levels = {
        CPEnum.KEY_EXCHANGE_ALG: [['ECDHE', 'DHE'], ['ECDH', 'DH'], [], []],
        CPEnum.CERT_SIG_ALG: [['ECDSA', 'RSA', 'DSS'], [], [], []],
        CPEnum.SYM_ENCRYPT_ALG: [['AES'], [], ['TDEA', '2DES', '3DES'], ['SKIPJACK']],
        CPEnum.SYM_ENCRYPT_ALG_KEY_LEN: [['AES128'], [], [], ['AES64']],
        CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE: [[], [], [], []],
        CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER: [[], ['CCM8'], [], []],
        CPEnum.HASH_FUN: [['SHA223', 'SHA256', 'SHA384'], ['SHA'], [], ['MD5']],
        CPEnum.HMAC: [[], [], [], []],
        CPEnum.PROTOCOL: [[], [], [], []],
        CPEnum.PROTOCOL_VERSION: [[], [], [], []],
        CPEnum.CERT_SIG_ALG_HASH_FUN: [[], [], [], []],
        CPEnum.CERT_SIG_ALG_KEY_LEN: [['RSA2048'], [], [], []]
    }

    def __init__(self, cert, cipher_suite, protocol):
        self.params = {}
        for enum in CPEnum:
            self.params[enum] = ['', 0]
        self.cert_version = str(cert.version.value)
        self.cert_serial_number = str(cert.serial_number)
        self.cert_not_valid_before = str(cert.not_valid_before.date())
        self.cert_not_valid_after = str(cert.not_valid_after.date())
        self.cert_subject = cert.subject
        self.cert_issuer = cert.issuer
        self.cipher_suite = cipher_suite
        self.parse_cipher_suite(cipher_suite)
        self.parse_protocol_version(protocol)
        self.params[CPEnum.CERT_SIG_ALG_KEY_LEN] = [str(cert.public_key().key_size), 0]
        self.params[CPEnum.CERT_SIG_ALG_HASH_FUN] = [str(cert.signature_hash_algorithm.name).upper(), 0]
        self.rating = 0

    def parse_cipher_suite(self, cipher_suite: str):
        raw_params = cipher_suite.split('_')
        raw_params.remove('TLS')
        file_names_cpy = FILE_NAMES.copy()
        for param in raw_params:
            file = ''
            for idx, file_name in enumerate(file_names_cpy):
                file = open(ROOT_DIR + '/../../resources/cipher_parameters/' + file_name, 'r')
                file_params = file.readline().split(',')
                if param in file_params:
                    file_names_cpy.pop(idx)
                    self.params[CPEnum(FILE_NAMES.index(file_name))] = [param, 0]
                    break
            file.close()

    def parse_protocol_version(self, protocol):
        self.params[CPEnum.PROTOCOL] = [protocol[:3], 0]
        self.params[CPEnum.PROTOCOL_VERSION] = [protocol[4:], 0]

    def rate_parameters(self):
        self.params[CPEnum.HASH_FUN][0] = 'SHA'
        self.params[CPEnum.SYM_ENCRYPT_ALG_KEY_LEN][0] = '64'
        self.params[CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER][0] = '8'
        self.params[CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE][0] = 'CCM'
        for enum in CPEnum:
            param = self.params[enum].copy()
            if enum == CPEnum.SYM_ENCRYPT_ALG_KEY_LEN:
                param[0] = self.params[CPEnum.SYM_ENCRYPT_ALG][0] + self.params[enum][0]
            elif enum == CPEnum.CERT_SIG_ALG_KEY_LEN:
                param[0] = self.params[CPEnum.CERT_SIG_ALG][0] + self.params[enum][0]
            elif enum == CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER:
                param[0] = self.params[CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE][0] + self.params[enum][0]
            for idx, level in enumerate(self.security_levels[enum]):
                if param[0] in level:
                    self.params[enum][1] = idx + 1
                    break
        self.rating = max([solo_rating[1] for solo_rating in self.params.values()])
