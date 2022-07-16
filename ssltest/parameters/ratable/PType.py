from enum import Enum, auto


class PType(Enum):
    protocol = auto()
    protocols = auto()
    no_protocol = auto()
    kex_algorithm = auto()
    kex_algorithm_mod = auto()
    cert_pub_key_algorithm = auto()
    cert_pub_key_length = auto()
    sym_enc_algorithm = auto()
    sym_enc_algorithm_mod = auto()
    sym_enc_algorithm_key_length = auto()
    sym_enc_algorithm_block_mode = auto()
    sym_ecn_algorithm_block_mode_number = auto()
    hash_function = auto()
    cert_sign_algorithm = auto()
    cert_sign_algorithm_hash_function = auto()
    hmac_function = auto()
    cert_version = auto()
    cert_serial_number = auto()
    cert_not_valid_before = auto()
    cert_not_valid_after = auto()
    cert_subject = auto()
    cert_issuer = auto()
    cert_alternative_names = auto()
    cert_verified = auto()

    @property
    def key_pair(self):
        """
        Define the algorithm to which the algorithm length belongs to

        :return: algorithm type
        :rtype: PType
        """
        pairs = {
            self.sym_enc_algorithm_key_length: self.sym_enc_algorithm,
            self.cert_pub_key_length: self.cert_pub_key_algorithm,
            self.sym_ecn_algorithm_block_mode_number: self.sym_enc_algorithm_block_mode,
        }
        return pairs[self]

    @property
    def is_cipher_suite(self):
        """
        Define which parameters are parsable from cipher suites

        :return: true if a parameter is parsable
        :rtype: bool
        """
        cipher_suite_parameters = [
            self.kex_algorithm,
            self.kex_algorithm_mod,
            self.sym_enc_algorithm,
            self.sym_enc_algorithm_mod,
            self.sym_enc_algorithm_key_length,
            self.sym_enc_algorithm_block_mode,
            self.sym_ecn_algorithm_block_mode_number,
            self.hash_function,
            self.hmac_function,
            self.cert_pub_key_algorithm,
        ]
        return self in cipher_suite_parameters

    @property
    def is_certificate(self):
        """
        Define which parameters are parsable from a certificate

        :return: true if a parameter is parsable
        :rtype: bool
        """
        certificate_parameters = [
            self.cert_pub_key_algorithm,
            self.cert_pub_key_length,
            self.cert_sign_algorithm,
            self.cert_sign_algorithm_hash_function,
            self.cert_version,
            self.cert_serial_number,
            self.cert_not_valid_before,
            self.cert_not_valid_after,
            self.cert_subject,
            self.cert_issuer,
            self.cert_alternative_names,
            self.cert_verified,
        ]
        return self in certificate_parameters

    @property
    def is_ratable(self):
        """
        Define which parameter can be rated

        :return: true if a parameter can be rated
        :rtype: bool
        """
        rateable_parameters = [
            self.kex_algorithm,
            self.kex_algorithm_mod,
            self.sym_enc_algorithm,
            self.sym_enc_algorithm_mod,
            self.sym_enc_algorithm_key_length,
            self.sym_enc_algorithm_block_mode,
            self.sym_ecn_algorithm_block_mode_number,
            self.hash_function,
            self.hmac_function,
            self.cert_pub_key_algorithm,
            self.cert_pub_key_length,
            self.cert_sign_algorithm,
            self.cert_sign_algorithm_hash_function,
            self.cert_verified,
        ]
        return self in rateable_parameters
