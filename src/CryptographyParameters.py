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


class CryptographyParameters:
    KEY_EXCHANGE_ALGORITHM = 0
    CERTIFICATE_SIGNATURE_ALGORITHM = 1
    SYMETRIC_ENCRYPTION_ALGORITHM = 2
    SYMETRIC_ENCRYPTION_ALGORITHM_LENGTH = 3
    SYMETRIC_ENCRYPTION_ALGORITHM_BLOCK_MODE = 4
    SYMETRIC_ENCRYPTION_ALGORITHM_BLOCK_MODE_NUMBER = 5
    HASH_FUNCTION = 6
    HMAC = 7
    PROTOCOL = 8
    PROTOCOL_VERSION = 9
    CERTIFICATE_SIGNATURE_ALGORITHM_HASH_FUNCTION = 10
    CERTIFICATE_SIGNATURE_ALGORITHM_KEY_LENGTH = 11

    def __init__(self):
        self.parameters = []
        for i in range(12):
            self.parameters.append('')

    def parse_cipher_suite(self, cipher_suite: str):
        raw_params = cipher_suite.split('_')
        raw_params.remove('TLS')
        file_names_cpy = FILE_NAMES.copy()
        for param in raw_params:
            for idx, file_name in enumerate(file_names_cpy):
                file = open(ROOT_DIR + '/../resources/cipher_parameters/' + file_name, 'r')
                file_params = file.readline().split(',')
                if param in file_params:
                    file_names_cpy.pop(idx)
                    self.parameters[FILE_NAMES.index(file_name)] = param
                    break
