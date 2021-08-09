class ConnectionTimeoutError(Exception):

    def __init__(self):
        super().__init__(f"Connection timed out")
