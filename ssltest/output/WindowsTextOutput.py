from .TextOutput import TextOutput


class WindowsTextOutput(TextOutput):

    @staticmethod
    def print_title(prefix_len, title_string, padding_char):
        print(title_string)

    @staticmethod
    def get_color_for_value(text):
        return text
