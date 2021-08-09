import json


class ptjsonlib:
    def __init__(self, json):
        self.json = json
        self.json_list = []

    def add_json(self, name):
        if self.json:
            json_template = {"test_code": name, "status": "null", "vulnerable": "null", "data": {}}
            self.json_list.append(json_template)
            return len(self.json_list) - 1
        else:
            pass

    def del_json(self, position):
        if self.json:
            self.json_list.pop(position)
        else:
            pass

    def add_data(self, position, data):
        if self.json:
            self.json_list[position]['data'].update(data)
        else:
            pass

    def set_testcode(self, position, testcode):
        if self.json:
            self.json_list[position].update({"testcode": testcode})
        else:
            pass

    def set_status(self, position, status, errormessage=""):
        if self.json:
            self.json_list[position].update({"status": status})
            if status == "error":
                self.json_list[position].update({"message": errormessage})
            else:
                pass

    def set_vulnerable(self, position, vulnerable):
        if self.json:
            self.json_list[position].update({"vulnerable": vulnerable})
        else:
            pass

    def get_json(self, position):
        if self.json:
            return json.dumps(self.json_list[position])
        else:
            pass

    def get_all_json(self):
        if self.json:
            return json.dumps(self.json_list)
        else:
            pass

    def get_status(self, position):
        if self.json:
            return self.json_list[position]["status"]
        else:
            pass
