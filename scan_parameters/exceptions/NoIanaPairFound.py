class NoIanaPairFound(Exception):

    def __init__(self):
        super().__init__(f"Error finding iana cipher suite format pair")
