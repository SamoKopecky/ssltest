import json

from scan_parameters.utils import read_json


class TextOutput:
    def __init__(self, data: str):
        self.output = ''
        self.ratings = read_json('security_levels_names.json')
        self.type_names = read_json('type_names.json')
        self.data = data
        self.current_data = {}

    def rating_name(self, rating: int):
        """
        Convert int to string using a json file.

        :param rating: rating value to be converted to string
        """
        return self.ratings[str(rating)]

    def text_output(self):
        """
        Call all other text output functions for each port and url.
        """
        if not self.data:
            return
        json_data = json.loads(self.data)
        for key, value in list(json_data.items()):
            self.output += f'----------------Result for {key}---------------------\n'
            self.current_data = value
            self.output_parameters(self.current_data['parameters'])
            self.output_supported_versions(self.current_data['protocol_support'])
            self.output_certificate_info(self.current_data['certificate_info'])
            self.output_software(self.current_data['web_server_software'])
            self.output_vulnerabilities(self.current_data['vulnerabilities'])
        self.output = self.output[:-1]

    def output_parameters(self, data: dict):
        """
        Output cipher suite and cert parameters.

        :param data: data to print
        """
        self.output += 'Cryptographic parameters:\n'
        for key, value in list(data.items()):
            if key == 'rating':
                self.output += f'\t{key}: {self.rating_name(value)}\n'
                continue
            values = list(value.items())[0]
            if values[0] != 'N/A':
                self.output += f'\t{self.type_names[key]}: {values[0]}->{self.rating_name(values[1])}\n'

    def output_certificate_info(self, data: dict):
        """
        Output other cert info such as subject/issuer.

        :param data: data to print
        """
        self.output += 'Certificate information:\n'
        for key, value in list(data.items()):
            if len(value) > 0:
                value = list(map(lambda el: f'\t\t{el}', value))
                values = '\n'.join(value)
                to_print = f'\t{self.type_names[key]}: \n{values}\n'
            elif not value:
                continue
            else:
                to_print = f'\t{self.type_names[key]}: {value[0]}\n'
            self.output += to_print

    def output_supported_versions(self, data: dict):
        """
        Output supported TLS protocol versions.

        :param data: data to print
        """
        self.output += 'Protocol support:\n'
        for key, values in list(data.items()):
            if key == 'rating':
                self.output += f'\t{key}: {self.rating_name(values)}\n'
                continue
            if len(values) > 0:
                versions = []
                for k, v in list(values.items()):
                    versions.append(f'\t\t{k}->{v}')
                values = '\n'.join(versions)
                self.output += f'\t{self.type_names[key]}:\n{values}\n'

    def output_software(self, data: dict):
        """
        Output web server software.

        :param data: data to print
        """
        if not data:
            return
        string_map = {
            'http_header': 'Http header',
            'nmap': 'Nmap'
        }
        self.output += 'Web server software:\n'
        for key, value in list(data.items()):
            self.output += f'\t{string_map.get(key)}: {value}\n'

    def output_vulnerabilities(self, data: dict):
        """
        Output scanned vulnerabilities

        :param data: data to print
        """
        if not data:
            return
        string_map = {
            True: 'Yes',
            False: 'No'
        }
        self.output += 'Scanned vulnerabilities:\n'
        for key, value in list(data.items()):
            self.output += f'\t{key}->{string_map.get(value)}\n'

    @staticmethod
    def dump_to_dict(cipher_suite, certificate_parameters, protocol_support,
                     certificate_non_parameters, software, vulnerabilities, port, url):
        """
        Dump web server parameters to a single dict.

        :param cipher_suite: tuple containing parameters and the worst rating
        :param certificate_parameters: tuple containing parameters and the worst rating
        :param certificate_non_parameters: certificate parameters such as subject/issuer
        :param protocol_support: dictionary of supported tls protocols
        :param software: web server software
        :param port: scanned port
        :param url: scanned url
        :param vulnerabilities: scanned vulnerabilities
        :return: dictionary
        """
        dump = {}

        # Parameters
        worst_rating = max([cipher_suite[1], certificate_parameters[1]])
        parameters = {key.name: value for key, value in cipher_suite[0].items()}
        parameters.update({key.name: value for key, value in certificate_parameters[0].items()})
        parameters.update({'rating': worst_rating})

        # Non ratable cert info
        certificate_info = {key.name: value for key, value in certificate_non_parameters.items()}

        # Protocol support
        protocols = {}
        keys = {key.name: value for key, value in protocol_support[0].items()}
        for key, value in list(keys.items()):
            protocols[key] = value
        protocols.update({'rating': protocol_support[1]})

        dump.update({'parameters': parameters})
        dump.update({'certificate_info': certificate_info})
        dump.update({'protocol_support': protocols})
        dump.update({'web_server_software': software})
        dump.update({'vulnerabilities': vulnerabilities})
        return {f'{url}:{port}': dump}
