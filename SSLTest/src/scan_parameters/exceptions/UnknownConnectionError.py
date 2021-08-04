class UnknownConnectionError(Exception):

    def __init__(self, exception):
        super().__init__(exception)
