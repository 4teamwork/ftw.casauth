from ftw.casauth.cas import strip_ticket
from ftw.casauth.cas import validate_ticket
from ftw.casauth.tests.utils import get_data
from ftw.casauth.tests.utils import MockResponse
from mock import patch

import unittest


class TestValdidateTicket(unittest.TestCase):

    @patch('ftw.casauth.cas.urllib2.urlopen')
    def test_validate_ticket_suceeds_with_valid_ticket(self, urlopen_mock):
        urlopen_mock.return_value = MockResponse(
            get_data('service_validate_success.xml'))
        self.assertEqual('james', validate_ticket(
            'ST-001-abc',
            'https://cas.domain.net',
            'https://service.domain.net'))

    @patch('ftw.casauth.cas.urllib2.urlopen')
    def test_validate_ticket_fails_with_invalid_ticket(self, urlopen_mock):
        urlopen_mock.return_value = MockResponse(
            get_data('service_validate_invalid_ticket.xml'))
        self.assertFalse(validate_ticket(
            'ST-001-abc',
            'https://cas.domain.net',
            'https://service.domain.net'))

    @patch('ftw.casauth.cas.urllib2.urlopen')
    def test_validate_ticket_fails_with_invalid_response(self, urlopen_mock):
        urlopen_mock.return_value = MockResponse("Invalid Response")
        self.assertFalse(validate_ticket(
            'ST-001-abc',
            'https://cas.domain.net',
            'https://service.domain.net'))

    @patch('ftw.casauth.cas.urllib2.urlopen')
    def test_validate_ticket_fails_with_invalid_xml_response(self, urlopen_mock):
        urlopen_mock.return_value = MockResponse("<resp>invalid</resp>")
        self.assertFalse(validate_ticket(
            'ST-001-abc',
            'https://cas.domain.net',
            'https://service.domain.net'))


class TestStripTicket(unittest.TestCase):

    def test_strip_ticket_drops_ticket_from_url(self):
        url = 'http://example.org?ticket=ST-001-abc&param1=v1&param2=v2'
        stripped = strip_ticket(url)
        self.assertEqual('http://example.org?param1=v1&param2=v2', stripped)

    def test_strip_ticket_preserves_multi_valued_params(self):
        url = 'http://example.org?ticket=ST-001-abc&multi=v1&multi=v2'
        stripped = strip_ticket(url)
        self.assertEqual('http://example.org?multi=v1&multi=v2', stripped)

    def test_strip_ticket_preserves_zope_style_multi_valued_params(self):
        url = 'http://example.org?ticket=ST-001-abc&multi:list=v1&multi:list=v2'
        stripped = strip_ticket(url)
        self.assertEqual('http://example.org?multi%3Alist=v1&multi%3Alist=v2', stripped)
