from scan_web_server.utils import *


class TextOutput:
    def __init__(self, data):
        self.ratings = {
            0: 'nezistené/chyba',
            1: 'bezpečné',
            2: 'nedoporúčané',
            3: 'zastarané',
            4: 'zakázané'
        }
        self.data = data
        self.first_port_data = {}
        self.type_names = read_json('type_names.json')

    def text_output(self):
        json_data = json.loads(self.data)
        self.first_port_data = list(json_data.values())[0]
        self.print_parameters(self.first_port_data['parameters'])
        self.print_supported_versions(self.first_port_data['protocol_support'])
        self.print_certificate_info(self.first_port_data['certificate_info'])
        self.print_versions(self.first_port_data['web_server_versions'])

    def print_parameters(self, data):
        print('Cryptographic parameters:')
        for key, value in list(data.items()):
            values = list(value.items())[0]
            if values[0] != 'N/A':
                print(f'\t{self.type_names[key]}: {values[0]}->{self.ratings[values[1]]}')

    def print_certificate_info(self, data):
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
        print('Protocol support:')
        for key, value in list(data.items()):
            print(f'\t{key}->{self.ratings[value]}')

    @staticmethod
    def print_versions(data):
        print('Web server versions')
        for key, value in list(data.items()):
            print(f'\t{key}: {value}')
