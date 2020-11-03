import re


class CryptographyParameters:
    def __init__(self):
        self.tls = False
        self.tls_version = 0
        self.key_exchange_algorithm = ""
        self.certificate_signature_algorithm = ""
        self.certificate_signature_algorithm_hash_function = ""
        self.certificate_signature_algorithm_key_length = 0
        self.symetric_encryption_algorithm = ""
        self.symetric_encryption_algorithm_block_mode = ""
        self.symetric_encryption_algorithm_block_mode_number = 0
        self.symetric_encryption_algorithm_key_length = 0
        self.cipher_suite_hash_function = ""
        self.hmac = ""

    def parse_cipher_suite(self, cipher_suite: str):
        items = cipher_suite.split('_')
        items.remove('TLS')

        print(items)
