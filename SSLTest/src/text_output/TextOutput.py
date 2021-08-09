import json
from ..utils import read_json


class TextOutput:
    def __init__(self, data: str):
        self.output = ''
        self.ratings = read_json('security_levels_names.json')
        self.type_names = read_json('english_strings.json')
        self.data = data
        self.current_data = {}

    def rating_name(self, rating: int):
        """
        Convert int to string using a json file.

        :param rating: rating value to be converted to string
        """
        return self.ratings[str(rating)]

    def get_formatted_text(self):
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
                    versions.append(f'\t\t{k}->{self.ratings[v]}')
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
