class NoWebServerVersionFoundError(Exception):
    """
    Attributes
        message -- return message after a raised exception
    """
    def __init__(self, message="Nebolo možné nájsť verziu serveru."):
        self.message = message
        super().__init__(self.message)
