from ftw.casauth.testing import FTW_CASAUTH_INTEGRATION_TESTING
from zope.publisher.browser import TestRequest
from plone.app.testing import TEST_USER_ID
from mock import patch
import unittest


class TestCASAuthPlugin(unittest.TestCase):

    layer = FTW_CASAUTH_INTEGRATION_TESTING

    def setUp(self):
        self.plugin = self.layer['plugin']

    def test_challenge_redirects_to_cas(self):
        request = TestRequest()
        response = request.response
        self.plugin.challenge(request, response)

        self.assertEqual(302, response.getStatus())
        self.assertEqual(
            'https://cas.domain.net/login?service=http%3A//127.0.0.1',
            response.getHeader('Location'))

    def test_challenge_doesnt_redirect_with_ticket(self):
        request = TestRequest()
        request.form.update(dict(ticket='ST-001-abc'))
        response = request.response
        self.plugin.challenge(request, response)

        self.assertEqual(599, response.getStatus())

    def test_extract_credentials_returns_ticket(self):
        request = TestRequest()
        request.form.update(dict(ticket='ST-001-abc'))
        creds = self.plugin.extractCredentials(request)

        self.assertIn('ticket', creds)
        self.assertEqual('ST-001-abc', creds['ticket'])

    def test_extract_credentials_returns_service_url(self):
        request = TestRequest(
            environ={'SERVER_URL': 'https://127.0.0.1/path'},
            form={'ticket': 'ST-001-abc'})
        creds = self.plugin.extractCredentials(request)

        self.assertIn('service_url', creds)
        self.assertEqual('https://127.0.0.1/path', creds['service_url'])

    def test_extract_credentials_without_ticket_returns_none(self):
        request = TestRequest()
        creds = self.plugin.extractCredentials(request)

        self.assertEqual(None, creds)

    @patch('ftw.casauth.plugin.validate_ticket')
    def test_authenticate_credentials_succeeds_with_valid_credentials(self, mock_validate_ticket):
        mock_validate_ticket.return_value = TEST_USER_ID
        creds = {
            'extractor': self.plugin.getId(),
            'ticket': 'ST-001-abc',
            'service_url': 'http://127.0.0.1/'
        }
        self.plugin.REQUEST = TestRequest()
        self.plugin.REQUEST.RESPONSE = self.plugin.REQUEST.response
        userid, login = self.plugin.authenticateCredentials(creds)
        self.assertEqual(TEST_USER_ID, userid)
        self.assertEqual(TEST_USER_ID, login)

    def test_authenticate_credentials_fails_with_wrong_extractor(self):
        creds = {
            'extractor': 'another-plugin',
            'ticket': 'ST-001-abc',
            'service_url': 'http://127.0.0.1/'
        }
        ret = self.plugin.authenticateCredentials(creds)
        self.assertEqual(None, ret)

    @patch('ftw.casauth.plugin.validate_ticket')
    def test_authenticate_credentials_fails_with_inexisting_user(self, mock_validate_ticket):
        mock_validate_ticket.return_value = 'james'
        creds = {
            'extractor': self.plugin.getId(),
            'ticket': 'ST-001-abc',
            'service_url': 'http://127.0.0.1/'
        }
        self.plugin.REQUEST = TestRequest()
        self.plugin.REQUEST.RESPONSE = self.plugin.REQUEST.response
        ret = self.plugin.authenticateCredentials(creds)
        self.assertEqual(None, ret)
