from .PType import PType
from ..utils import *


class Certificate:

    def __init__(self, certificate):
        # Create a dictionary for certificate parameters with PType keys
        self.parameters = {enum: ['N/A', 0] for enum in PType if enum.is_certificate}
        self.certificate = certificate
        self.rating = 0

    def parse_certificate(self):
        """
        Parses information from a certificate and parses it into a dictionary.
        """
        self.parameters[PType.cert_pub_key_algorithm][0] = pub_key_alg_from_cert(self.certificate.public_key())
        self.parameters[PType.cert_version][0] = str(self.certificate.version.value)
        self.parameters[PType.cert_serial_number][0] = str(self.certificate.serial_number)
        self.parameters[PType.cert_not_valid_before][0] = str(self.certificate.not_valid_before.date())
        self.parameters[PType.cert_not_valid_after][0] = str(self.certificate.not_valid_after.date())
        self.parameters[PType.cert_alternative_names][0] = self.parse_alternative_names()
        self.parse_name(PType.cert_subject, self.certificate.subject)
        self.parse_name(PType.cert_issuer, self.certificate.issuer)
        self.parameters[PType.cert_issuer][0] = self.parameters[PType.cert_issuer][0][:-1]
        self.parameters[PType.cert_sign_algorithm][0] = get_sig_alg_from_oid(
            self.certificate.signature_algorithm_oid)
        self.parameters[PType.cert_sign_algorithm_hash_function][0] = str(
            self.certificate.signature_hash_algorithm.name).upper()
        self.parameters[PType.cert_pub_key_length][0] = str(self.certificate.public_key().key_size)

    def parse_alternative_names(self):
        """
        Parses the alternative names from the certificate extensions.

        :return: list of alternative names
        """
        extension = self.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return extension.value.get_values_for_type(x509.DNSName)

    def parse_name(self, name_type, name):
        """
        Helper function for gathering subject and issuer information.

        :param name_type: PType enum
        :param name: objects that is parsed
        :return:
        """
        self.parameters[name_type][0] = []
        for attribute in name:
            self.parameters[name_type][0].append(f'{attribute.oid._name}={attribute.value},')
        self.parameters[name_type][0] = self.parameters[name_type][0][:-1]

    def rate_certificate(self):
        """
        Rates all valid certificate parameters.

        First part is used if a length parameter needs to be rated.
        Second part is used for not length parameters.
        """
        certificate_types = list(self.parameters.keys())
        rateable_parameters = [enum for enum in certificate_types if enum.is_ratable]
        for enum in rateable_parameters:
            # 1st part
            if enum == PType.cert_pub_key_length:
                self.parameters[enum][1] = rate_key_length_parameter(
                    self.parameters[enum.key_pair][0],
                    self.parameters[enum][0], enum
                )
                continue
            # 2nd part
            self.parameters[enum][1] = rate_parameter(enum, self.parameters[enum][0])
        self.rating = max([solo_rating[1] for solo_rating in self.parameters.values()])

    def rate(self):
        self.parse_certificate()
        self.rate_certificate()
        return self.rating
