import os.path


def get_data(filename):
    """Return content from a file in the test data folder """
    filename = os.path.join(os.path.dirname(__file__), 'data', filename)
    return open(filename, 'r').read()


class MockRequest(object):

    def get_type(self):
        return 'https'


class MockResponse(object):

    def __init__(self, data, code=200, msg='OK'):
        self.data = data
        self.code = code
        self.msg = msg

    def read(self):
        return self.data

    def getcode(self):
        return self.code

    def info(self):
        return {}
