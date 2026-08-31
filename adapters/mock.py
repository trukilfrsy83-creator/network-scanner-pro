class MockNetworkAdapter:

    def __init__(self):

        self.blocked = set()

    def block(self, ip):

        self.blocked.add(ip)

        return True

    def unblock(self, ip):

        self.blocked.discard(ip)

        return True

    def is_blocked(self, ip):

        return ip in self.blocked
