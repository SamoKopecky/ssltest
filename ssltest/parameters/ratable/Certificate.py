import logging

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
from cryptography.x509 import SubjectAlternativeName, DNSName, SignatureAlgorithmOID
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509 import Certificate as cryptoCert

from .PType import PType
from .Parameters import Parameters

log = logging.getLogger(__name__)


class Certificate(Parameters):
    def __init__(self, certificates, cert_verified, args):
        """
        Constructor

        :param list[cryptoCert] certificates: List of certificates
        :param bool cert_verified: Is certificate verified
        :param argparse.Namespace args: Limit alternative names output
        """
        super().__init__()
        self.verified = cert_verified
        # Create a dictionary for certificate parameters with PType keys
        self.non_parameters = {}
        self.all_non_parameters = {}
        self.first_cert_parameters = {}
        self.other_certs_parameters = []
        self.certificates = certificates
        self.cert_chain = args.cert_chain
        self.reset_params()
        self.ratings = []

    def reset_params(self):
        """
        Reset the parameters so that they don't contain anything
        """
        # Parameters that can be rated (Signature algorithm, ...)
        self.parameters = {
            p_type: {}
            for p_type in PType
            if p_type.is_certificate and p_type.is_ratable
        }
        # Parameters that can't be rated (Subject, Issuer, ...)
        self.non_parameters = {
            p_type: []
            for p_type in PType
            if p_type.is_certificate and not p_type.is_ratable
        }

    def parse_certificates(self):
        """
        Parse the certificate chain
        """
        for i, certificate in enumerate(self.certificates):
            self.parse_certificate(certificate)
            self.all_non_parameters.update({f"certificate_{i}": self.non_parameters})
            if i == 0:
                self.first_cert_parameters = self.parameters
            else:
                self.other_certs_parameters.append(self.parameters)
            self.reset_params()

    def parse_certificate(self, certificate):
        """
        Parse information from a certificate into a dictionary

        :param cryptoParam certificate: A certificate to parse
        """
        log.info("Parsing certificate")
        # Public key algorithm
        self.parameters[PType.cert_pub_key_algorithm][
            self.pub_key_alg_from_cert(certificate.public_key())
        ] = 0
        # Public key length
        self.parameters[PType.cert_pub_key_length][
            str(certificate.public_key().key_size)
        ] = 0
        # Certificate hash function
        hash_function = str(certificate.signature_hash_algorithm.name).upper()
        self.parameters[PType.cert_sign_algorithm_hash_function][hash_function] = 0
        # Signature algorithm
        sign_algorithm = self.get_sig_alg_from_oid(certificate.signature_algorithm_oid)
        self.parameters[PType.cert_sign_algorithm][sign_algorithm] = 0
        # Certificate verified
        self.parameters[PType.cert_verified][str(self.verified)] = 0
        # Other non-ratable parameters
        self.non_parameters[PType.cert_version].append(str(certificate.version.value))
        self.non_parameters[PType.cert_serial_number].append(
            str(certificate.serial_number)
        )
        self.non_parameters[PType.cert_not_valid_before].append(
            str(certificate.not_valid_before.date())
        )
        self.non_parameters[PType.cert_not_valid_after].append(
            str(certificate.not_valid_after.date())
        )
        self.non_parameters[
            PType.cert_alternative_names
        ] = self.parse_alternative_names(certificate)
        self.non_parameters[PType.cert_subject] = self.parse_name(certificate.subject)
        self.non_parameters[PType.cert_issuer] = self.parse_name(certificate.issuer)

    def rate_certificate(self, parameters):
        """
        Rate all valid certificate parameters

        :param dict parameters: Cert parameters to rate
        :return: Rated parameters
        :rtype: dict
        """
        rateable_parameters = list(parameters)
        key_types = [PType.cert_pub_key_length]
        self.parameters = parameters
        self.rate_parameters(rateable_parameters, key_types)
        self.ratings.append(self.rating)
        return self.parameters

    def rate_certificates(self):
        """
        Rate the whole certificate chain
        """
        self.first_cert_parameters = self.rate_certificate(self.first_cert_parameters)
        for i, value in enumerate(self.other_certs_parameters):
            self.other_certs_parameters[i] = self.rate_certificate(value)
        self.rating = max(self.ratings)

    def get_json(self):
        """
        Get non-ratable parameters as json

        :return: Json version of all non-ratable parameters
        :rtype: dict
        """

        def to_json(items):
            return {key.name: value for key, value in items}

        if not self.cert_chain:
            return to_json(self.all_non_parameters.pop("certificate_0").items())
        return {
            key: to_json(value.items())
            for key, value in self.all_non_parameters.items()
        }

    @staticmethod
    def parse_alternative_names(certificate):
        """
        Parse the alternative names from the certificate extensions

        :param cryptography.x509.Certificate certificate: Certificate to parse
        :return: Alternative names
        :rtype: list[str]
        """
        log.info("Parsing alternative names from certificate")
        try:
            extension = certificate.extensions.get_extension_for_class(
                SubjectAlternativeName
            )
        except ExtensionNotFound:
            log.error("No alternative names extension found in certificate")
            return []
        alternative_names: list = extension.value.get_values_for_type(DNSName)
        if len(alternative_names) == 0:
            log.debug("No alternative names found")
        return alternative_names

    @staticmethod
    def parse_name(name):
        """
        Parse subject and issuer information and return as list

        :param cryptography.x509.name.Name name: objects that is parsed
        :return: Parsed subject or issuer
        :rtype: list
        """
        log.info("Parsing subject/issuer")
        name_info = []
        for attribute in name:
            name_info.append(f"{attribute.oid._name}: {attribute.value}")
        return name_info

    @staticmethod
    def pub_key_alg_from_cert(public_key):
        """
        Get the public key algorithm from a certificate

        :param public_key: Instance of a public key
        :return: Parsed parameter
        :rtype: str
        """
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return "EC"
        elif isinstance(public_key, rsa.RSAPublicKey):
            return "RSA"
        elif isinstance(public_key, dsa.DSAPublicKey):
            return "DSA"
        elif isinstance(public_key, ed25519.Ed25519PublicKey) or isinstance(
            public_key, ed448.Ed448PublicKey
        ):
            return "ECDSA"
        else:
            log.error("Unknown type for certificate public key ")
            return "N/A"

    @staticmethod
    def get_sig_alg_from_oid(oid):
        """
        Get a signature algorithm from an oid of a certificate

        :param cryptography.hazmat._oid.ObjectIdentifier oid: Object identifier
        :return: Signature algorithm
        :rtype: str
        """
        values = list(SignatureAlgorithmOID.__dict__.values())
        keys = list(SignatureAlgorithmOID.__dict__.keys())
        return keys[values.index(oid)].split("_")[0]
