import os

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
    KEY_EXCHANGE_ALG = 0
    CERT_SIG_ALG = 1
    SYM_ENCRYPT_ALG = 2
    SYM_ENCRYPT_ALG_KEY_LEN = 3
    SYM_ENCRYPT_ALGO_BLOCK_MODE = 4
    SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER = 5
    HASH_FUN = 6
    HMAC = 7
    PROTOCOL = 8
    PROTOCOL_VERSION = 9
    CERT_SIG_ALG_HASH_FUN = 10
    CERT_SIG_ALG_KEY_LEN = 11

    def __init__(self, cert, cipher_suite, protocol):
        self.params = []
        for i in range(12):
            self.params.append('')
        self.cert_version = str(cert.version.value)
        self.cert_serial_number = str(cert.serial_number)
        self.cert_not_valid_before = str(cert.not_valid_before.date())
        self.cert_not_valid_after = str(cert.not_valid_after.date())
        self.cert_subject = cert.subject
        self.cert_issuer = cert.issuer
        self.params[self.CERT_SIG_ALG_KEY_LEN] = cert.public_key().key_size
        self.params[self.CERT_SIG_ALG_HASH_FUN] = str(cert.signature_hash_algorithm.name).upper()
        self.cipher_suite = cipher_suite
        self.parse_cipher_suite(cipher_suite)
        self.parse_protocol_version(protocol)

    def parse_cipher_suite(self, cipher_suite: str):
        raw_params = cipher_suite.split('_')
        raw_params.remove('TLS')
        file_names_cpy = FILE_NAMES.copy()
        for param in raw_params:
            for idx, file_name in enumerate(file_names_cpy):
                file = open(ROOT_DIR + '/../../resources/cipher_parameters/' + file_name, 'r')
                file_params = file.readline().split(',')
                if param in file_params:
                    file_names_cpy.pop(idx)
                    self.params[FILE_NAMES.index(file_name)] = param
                    break

    def parse_protocol_version(self, protocol):
        self.params[self.PROTOCOL] = protocol[:3]
        self.params[self.PROTOCOL_VERSION] = protocol[4:]
