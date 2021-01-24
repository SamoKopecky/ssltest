class NoWebServerVersionFoundError(Exception):
    """
    TODO: Docs
    """
    def __init__(self, message="Nebolo možné nájsť verziu serveru."):
        self.message = message
        super().__init__(self.message)
