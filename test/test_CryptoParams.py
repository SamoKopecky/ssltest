import unittest
from src.logic.CryptoParams import CryptoParams
from src.logic import session_info
from src.logic.CryptoParamsEnum import CryptoParamsEnum as CPEnum


class TestCryptoParams(unittest.TestCase):

    def test_parse_protocol_version(self):
        self.cert, self.cipher_suite, self.protocol = session_info.get_website_info('google.com')
        params = CryptoParams(self.cert, self.cipher_suite, 'TLSv1.2')
        params.parse_protocol_version()
        self.assertEqual(params.params[CPEnum.PROTOCOL][0], 'TLS')
        self.assertEqual(params.params[CPEnum.PROTOCOL_VERSION][0], '1.2')
        params.protocol = 'SSLv3'
        params.parse_protocol_version()
        self.assertEqual(params.params[CPEnum.PROTOCOL][0], 'SSL')
        self.assertEqual(params.params[CPEnum.PROTOCOL_VERSION][0], '3')

    def test_rate_parameters(self):
        self.cert, self.cipher_suite, self.protocol = session_info.get_website_info('google.com')
        params = CryptoParams(self.cert, self.cipher_suite, self.protocol)
        params.parse_protocol_version()
        params.parse_cipher_suite()
        params.params[CPEnum.HASH_FUN][0] = 'SHA'
        params.params[CPEnum.SYM_ENCRYPT_ALG_KEY_LEN][0] = '64'
        params.params[CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER][0] = '8'
        params.params[CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE][0] = 'CCM'
        params.params[CPEnum.CERT_PUB_KEY_ALG][0] = 'RSA'
        params.params[CPEnum.CERT_PUB_KEY_LEN][0] = '1500'
        params.rate_parameters()
        self.assertEqual(params.params[CPEnum.HASH_FUN][1], 2)
        self.assertEqual(params.params[CPEnum.SYM_ENCRYPT_ALG_KEY_LEN][1], 4)
        self.assertEqual(params.params[CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE_NUMBER][1], 2)
        self.assertEqual(params.params[CPEnum.SYM_ENCRYPT_ALG_BLOCK_MODE][1], 1)
        self.assertEqual(params.params[CPEnum.CERT_PUB_KEY_LEN][1], 3)
