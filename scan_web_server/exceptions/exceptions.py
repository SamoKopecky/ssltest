class NoWebServerVersionFoundError(Exception):
    """
    Attributes
        message -- return message after a raised exception
    """

    def __init__(self, method, message="Nebolo možné nájsť verziu serveru."):
        self.message = message
        self.method = method
        super().__init__(self.message)
