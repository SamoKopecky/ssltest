import json

from ..utils import read_json


class TextOutput:
    def __init__(self, data: str):
        self.output = ''
        self.ratings = read_json('security_levels_names.json')
        self.type_names = read_json('english_strings.json')
        self.data = data
        self.current_data = {}

    def get_formatted_text(self):
        """
        Call all other text output functions for each port and url
        """
        if not self.data:
            return
        json_data = json.loads(self.data)
        for key, value in list(json_data.items()):
            self.output += f'----------------Result for {key}---------------------\n'
            self.current_data = value
            self.format_parameters(self.current_data['parameters'])
            self.format_supported_versions(self.current_data['protocol_support'])
            self.format_certificate_info(self.current_data['certificate_info'])
            self.format_software(self.current_data['web_server_software'])
            self.format_cipher_suites(self.current_data['cipher_suites'])
            self.format_vulnerabilities(self.current_data['vulnerabilities'])
        self.output = self.output[:-1]

    def format_parameters(self, data):
        """
        Format the cipher suite and certificate parameters

        :param dict data: Data to format
        """
        self.output += 'Cryptographic parameters:\n'
        for key, value in list(data.items()):
            if key == 'rating':
                self.output += f'\t{key}: {self.ratings[value]}\n'
                continue
            values = list(value.items())[0]
            if values[0] != 'N/A':
                self.output += f'\t{self.type_names[key]}: {values[0]}->{self.ratings[values[1]]}\n'

    def format_certificate_info(self, data):
        """
        Format other certificate info such as subject/issuer

        :param dict data: Data to format
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

    def format_supported_versions(self, data):
        """
        Format supported SSL/TLS protocol versions

        :param dict data: Data to format
        """
        self.output += 'Protocol support:\n'
        for key, values in list(data.items()):
            if key == 'rating':
                self.output += f'\t{key}: {self.ratings[values]}\n'
                continue
            if len(values) > 0:
                versions = []
                for k, v in list(values.items()):
                    versions.append(f'\t\t{k}->{self.ratings[v]}')
                values = '\n'.join(versions)
                self.output += f'\t{self.type_names[key]}:\n{values}\n'

    def format_software(self, data):
        """
        Format web server software

        :param dict data: Data to format
        """
        if not data:
            return
        self.output += 'Web server software:\n'
        for key, value in list(data.items()):
            self.output += f'\t{self.type_names[key]}: {value}\n'

    def format_cipher_suites(self, data):
        """
        Format supported cipher suites

        :param data: Data to format
        """
        if not data:
            return
        self.output += 'Supported cipher suites:\n'
        for key, value in data.items():
            if type(value) is dict:
                value = list(map(lambda cs: f'\t\t{cs[0]}->{cs[1]}', value.items()))
                value = '\n'.join(value)
            self.output += f'\t{key}: \n{value}\n'

    def format_vulnerabilities(self, data):
        """
        Format scanned vulnerabilities

        :param dict data: Data to format
        """
        if not data:
            return
        string_map = {
            True: 'Yes',
            False: 'No'
        }
        self.output += 'Scanned vulnerabilities:\n'
        for key, value in list(data.items()):
            self.output += f'\t{key}->{string_map[value]}\n'
