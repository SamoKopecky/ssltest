from pprint import pprint

from scan_web_server.utils import *


class TextOutput:
    def __init__(self, data):
        self.ratings = read_json('security_levels_names.json')
        self.type_names = read_json('type_names.json')
        self.data = data
        self.current_data = {}

    def rating_name(self, rating):
        """
        Convert int to string using a json file.

        :param rating: integer
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
            self.print_versions(self.current_data['web_server_versions'])

    def print_parameters(self, data):
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

    def print_certificate_info(self, data):
        """
        Print other cert info such as subject/issuer.

        :param data: data to print
        :return:
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

    def print_supported_versions(self, data):
        """
        Print supported TLS protocol versions.

        :param data: data to print
        :return:
        """
        print('Protocol support:')
        for key, value in list(data.items()):
            if key == 'rating':
                print(f'\t{key}: {self.rating_name(value)}')
                continue
            print(f'\t{key}->{self.rating_name(value)}')

    @staticmethod
    def print_versions(data):
        """
        Print web server versions.

        :param data: data to print
        :return:
        """
        print('Web server versions')
        for key, value in list(data.items()):
            print(f'\t{key}: {value}')
