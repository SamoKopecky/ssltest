import json

from scan_parameters.utils import read_json
from scan_parameters.ratable.PType import PType


class TextOutput:
    def __init__(self, data: str):
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
            print(f'----------------Result for {key}---------------------')
            self.current_data = value
            self.print_parameters(self.current_data['parameters'])
            self.print_supported_versions(self.current_data['protocol_support'])
            self.print_certificate_info(self.current_data['certificate_info'])
            self.print_software(self.current_data['web_server_software'])
            self.print_vulnerabilities(self.current_data['vulnerabilities'])

    def print_parameters(self, data: dict):
        """
        Print cipher suite and cert parameters.

        :param data: data to print
        """
        print('Cryptographic parameters:')
        for key, value in list(data.items()):
            if key == 'rating':
                print(f'\t{key}: {self.rating_name(value)}')
                continue
            values = list(value.items())[0]
            if values[0] != 'N/A':
                print(f'\t{self.type_names[key]}: {values[0]}->{self.rating_name(values[1])}')

    def print_certificate_info(self, data: dict):
        """
        Print other cert info such as subject/issuer.

        :param data: data to print
        """
        print('Certificate information:')
        for key, value in list(data.items()):
            if len(value) > 1:
                value = list(map(lambda el: f'\t\t{el}', value))
                values = '\n'.join(value)
                to_print = f'\t{self.type_names[key]}: \n{values}'
            elif not value:
                continue
            else:
                to_print = f'\t{self.type_names[key]}: {value[0]}'
            print(to_print)

    def print_supported_versions(self, data: dict):
        """
        Print supported TLS protocol versions.

        :param data: data to print
        """
        print('Protocol support:')
        for key, values in list(data.items()):
            if key == 'rating':
                print(f'\t{key}: {self.rating_name(values)}')
                continue
            if len(values) > 1:
                output = []
                for k, v in list(values.items()):
                    output.append(f'\t\t{k}->{v}')
                values = '\n'.join(output)
            print(f'\t{self.type_names[key]}:\n{values}')

    @staticmethod
    def print_software(data: dict):
        """
        Print web server software.

        :param data: data to print
        """
        if not data:
            return
        string_map = {
            'http_header': 'Http header',
            'nmap': 'Nmap'
        }
        print('Web server software:')
        for key, value in list(data.items()):
            print(f'\t{string_map.get(key)}: {value}')

    @staticmethod
    def print_vulnerabilities(data: dict):
        """
        Print scanned vulnerabilities

        :param data: data to print
        """
        if not data:
            return
        string_map = {
            True: 'Yes',
            False: 'No'
        }
        print('Scanned vulnerabilities:')
        for key, value in list(data.items()):
            print(f'\t{key}->{string_map.get(value)}')

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
