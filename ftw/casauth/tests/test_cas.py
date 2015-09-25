import unittest
from ftw.casauth.tests.utils import MockRequest
from ftw.casauth.tests.utils import MockResponse
from ftw.casauth.tests.utils import get_data
from ftw.casauth.cas import validate_ticket
from mock import patch


class TestValdidateTicket(unittest.TestCase):

    @patch('ftw.casauth.cas.HTTPSHandler', autospec=True)
    def test_validate_ticket_suceeds_with_valid_ticket(self, MockHTTPSHandler):
        MockHTTPSHandler.https_request.return_value = MockRequest()
        MockHTTPSHandler.https_open.return_value = MockResponse(
            get_data('service_validate_success.xml'))
        self.assertEqual('james', validate_ticket(
            'ST-001-abc',
            'https://cas.domain.net',
            'https://service.domain.net'))

    @patch('ftw.casauth.cas.HTTPSHandler', autospec=True)
    def test_validate_ticket_fails_with_invalid_ticket(self, MockHTTPSHandler):
        MockHTTPSHandler.https_request.return_value = MockRequest()
        MockHTTPSHandler.https_open.return_value = MockResponse(
            get_data('service_validate_invalid_ticket.xml'))
        self.assertFalse(validate_ticket(
            'ST-001-abc',
            'https://cas.domain.net',
            'https://service.domain.net'))

    @patch('ftw.casauth.cas.HTTPSHandler', autospec=True)
    def test_validate_ticket_fails_with_invalid_response(self, MockHTTPSHandler):
        MockHTTPSHandler.https_request.return_value = MockRequest()
        MockHTTPSHandler.https_open.return_value = MockResponse("Invalid Response")
        self.assertFalse(validate_ticket(
            'ST-001-abc',
            'https://cas.domain.net',
            'https://service.domain.net'))

    @patch('ftw.casauth.cas.HTTPSHandler', autospec=True)
    def test_validate_ticket_fails_with_invalid_xml_response(self, MockHTTPSHandler):
        MockHTTPSHandler.https_request.return_value = MockRequest()
        MockHTTPSHandler.https_open.return_value = MockResponse("<resp>invalid</resp>")
        self.assertFalse(validate_ticket(
            'ST-001-abc',
            'https://cas.domain.net',
            'https://service.domain.net'))
