class DNSError(Exception):

    def __init__(self):
        super().__init__(f"No DNS record found")
