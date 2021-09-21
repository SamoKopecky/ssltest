class ConnectionTimeout(Exception):
    def __init__(self):
        self.message = 'Connection timeout out'
        super().__init__(self.message)
