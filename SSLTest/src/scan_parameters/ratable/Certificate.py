import logging

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448

from .PType import PType
from .Parameters import Parameters

log = logging.getLogger(__name__)


class Certificate(Parameters):
    def __init__(self, certificate, cert_verified, short_cert):
        """
        Constructor

        :param x509.Certificate certificate: Certificate
        :param bool cert_verified: Is certificate verified
        :param bool short_cert: Limit alternative names output
        """
        super().__init__()
        self.verified = cert_verified
        # Create a dictionary for certificate parameters with PType keys
        # Parameters that can be rated (Signature algorithm, ...)
        self.parameters = {
            p_type: {} for p_type in PType if p_type.is_certificate and p_type.is_ratable}
        # Parameters that can't be rated (Subject, Issuer, ...)
        self.non_parameters = {
            p_type: [] for p_type in PType if p_type.is_certificate and not p_type.is_ratable}
        self.certificate = certificate
        self.short_cert = short_cert

    def parse_certificate(self):
        """
        Parse information from a certificate and into a dictionary
        """
        # Public key algorithm
        self.parameters[PType.cert_pub_key_algorithm][
            self.pub_key_alg_from_cert(self.certificate.public_key())] = 0
        # Public key length
        self.parameters[PType.cert_pub_key_length][
            str(self.certificate.public_key().key_size)] = 0
        # Certificate hash function
        hash_function = str(
            self.certificate.signature_hash_algorithm.name).upper()
        self.parameters[PType.cert_sign_algorithm_hash_function][hash_function] = 0
        # Signature algorithm
        sign_algorithm = self.get_sig_alg_from_oid(
            self.certificate.signature_algorithm_oid)
        self.parameters[PType.cert_sign_algorithm][sign_algorithm] = 0
        # Certificate verified
        self.parameters[PType.cert_verified][str(self.verified)] = 0
        # Other non-ratable parameters
        self.non_parameters[PType.cert_version] \
            .append(str(self.certificate.version.value))
        self.non_parameters[PType.cert_serial_number] \
            .append(str(self.certificate.serial_number))
        self.non_parameters[PType.cert_not_valid_before] \
            .append(str(self.certificate.not_valid_before.date()))
        self.non_parameters[PType.cert_not_valid_after]. \
            append(str(self.certificate.not_valid_after.date()))
        self.non_parameters[PType.cert_alternative_names] = \
            self.parse_alternative_names()
        self.non_parameters[PType.cert_subject] = \
            self.parse_name(self.certificate.subject)
        self.non_parameters[PType.cert_issuer] = \
            self.parse_name(self.certificate.issuer)

    def parse_alternative_names(self):
        """
        Parse the alternative names from the certificate extensions

        :return: Alternative names
        :rtype: list
        """
        try:
            extension = self.certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName)
        except x509.extensions.ExtensionNotFound:
            log.error('No alternative names extension found in certificate')
            return []
        alternative_names: list = extension.value.get_values_for_type(
            x509.DNSName)
        if self.short_cert and len(alternative_names) > 5:
            return alternative_names[:5] + ['...']
        return alternative_names

    @staticmethod
    def parse_name(name):
        """
        Parse subject and issuer information and return as list

        :param x509.Certificate.__name__ name: objects that is parsed
        :return: Parsed subject or issuer
        :rtype: list
        """
        name_info = []
        for attribute in name:
            name_info.append(f'{attribute.oid._name}: {attribute.value}')
        return name_info

    def rate_certificate(self):
        """
        Rate all valid certificate parameters
        """
        rateable_parameters = list(self.parameters.keys())
        key_types = [PType.cert_pub_key_length]
        self.rate_parameters(rateable_parameters, key_types)

    @staticmethod
    def pub_key_alg_from_cert(public_key):
        """
        Get the public key algorithm from a certificate

        :param public_key: Instance of a public key
        :return: Parameter
        :rtype: str
        """
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return 'EC'
        elif isinstance(public_key, rsa.RSAPublicKey):
            return 'RSA'
        elif isinstance(public_key, dsa.DSAPublicKey):
            return 'DSA'
        elif isinstance(public_key, ed25519.Ed25519PublicKey) or isinstance(public_key, ed448.Ed448PublicKey):
            return 'ECDSA'
        else:
            log.error('Unknown type for certificate public key ')
            return 'N/A'

    @staticmethod
    def get_sig_alg_from_oid(oid):
        """
        Get a signature algorithm from an oid of a certificate

        :param x509.ObjectIdentifier oid: Object identifier
        :return: Signature algorithm
        :rtype: str
        """
        values = list(x509.SignatureAlgorithmOID.__dict__.values())
        keys = list(x509.SignatureAlgorithmOID.__dict__.keys())
        return keys[values.index(oid)].split('_')[0]

    def get_json(self):
        return {key.name: value for key, value in self.non_parameters.items()}
