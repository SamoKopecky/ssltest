from src.parser.CryptoParamsEnum import CryptoParamsEnum as CPEnum
from src.utils import read_json, compare_key_length


class CryptoParams:

    def __init__(self, cert, cipher_suite, protocol):
        self.params = {}
        for enum in CPEnum:
            self.params[enum] = ['N/A', 0]
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
        jdata = read_json('cipher_parameters.json')
        raw_params = cipher_suite.split('_')
        raw_params.remove('TLS')
        cipher_suite_enums = [CPEnum(enum_val) for enum_val in
                              range(CPEnum.KEY_EXCHANGE_ALG.value, CPEnum.HMAC.value + 1)]
        for param in raw_params:
            for enum in cipher_suite_enums:
                file_params = jdata[enum.name]['PARAMETERS'].split(',')
                if param in file_params:
                    cipher_suite_enums.remove(enum)
                    self.params[enum] = [param, 0]
                    break
        if self.params[CPEnum.CERT_SIG_ALG][0] == 'N/A' and self.params[CPEnum.KEY_EXCHANGE_ALG][0] == 'RSA':
            self.params[CPEnum.CERT_SIG_ALG][0] = 'RSA'

    def parse_protocol_version(self, protocol):
        self.params[CPEnum.PROTOCOL] = [protocol[:3], 0]
        self.params[CPEnum.PROTOCOL_VERSION] = [protocol[4:], 0]

    def rate_parameters(self):
        # self.params[CPEnum.HASH_FUN][0] = 'SHA'
        # self.params[CPEnum.SYM_ENCRYPT_ALG_KEY_LEN][0] = '64'
        # self.params[CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER][0] = '8'
        # self.params[CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE][0] = 'CCM'
        # self.params[CPEnum.CERT_SIG_ALG_KEY_LEN][0] = '1500'
        jdata = read_json('security_levels.json')

        for enum in CPEnum:
            param = self.params[enum].copy()
            if enum == CPEnum.SYM_ENCRYPT_ALG_KEY_LEN or \
                    enum == CPEnum.CERT_SIG_ALG_KEY_LEN or \
                    enum == CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER:
                self.params[enum][1] = compare_key_length(self.params[CPEnum.get_key_pair(enum)][0], param[0],
                                                          jdata[enum.name])
            for idx in range(1, 5):
                if param[0] in jdata[enum.name][str(idx)].split(','):
                    self.params[enum][1] = idx
                    break
        self.rating = max([solo_rating[1] for solo_rating in self.params.values()])
