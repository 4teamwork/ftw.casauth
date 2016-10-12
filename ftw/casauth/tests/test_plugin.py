from collections import OrderedDict
from DateTime import DateTime
from datetime import datetime
from ftw.casauth.testing import FTW_CASAUTH_INTEGRATION_TESTING
from ftw.testing import freeze
from mock import patch
from plone.app.testing import TEST_USER_ID
from Products.CMFCore.utils import getToolByName
from urllib import urlencode
from zope.component.hooks import getSite
import unittest


class TestCASAuthPlugin(unittest.TestCase):

    layer = FTW_CASAUTH_INTEGRATION_TESTING

    def setUp(self):
        self.plugin = self.layer['plugin']
        self.request = self.layer['request']

    def test_challenge_redirects_to_cas(self):
        response = self.request.response
        self.assertTrue(self.plugin.challenge(self.request, response))

        self.assertEqual(302, response.getStatus())
        self.assertEqual(
            'https://cas.domain.net/login?service=http%3A//nohost',
            response.getHeader('Location'))

    def test_challenge_doesnt_redirect_with_ticket(self):
        self.request.form.update(dict(ticket='ST-001-abc'))
        response = self.request.response
        self.assertFalse(self.plugin.challenge(self.request, response))

        self.assertEqual(200, response.getStatus())

    def test_challenge_redirect_includes_query_string(self):
        self.request.environ['QUERY_STRING'] = 'param1=value1&param2=value2'
        response = self.request.response

        self.assertTrue(self.plugin.challenge(self.request, response))

        self.assertEqual(302, response.getStatus())
        self.assertEqual(
            'https://cas.domain.net/login?service=http%3A//nohost%3Fparam1%3Dvalue1%26param2%3Dvalue2',
            response.getHeader('Location'))

    def test_challenge_doesnt_redirect_with_missing_cas_server_url(self):
        self.plugin.cas_server_url = None
        response = self.request.response
        self.assertFalse(self.plugin.challenge(self.request, response))

    def test_extract_credentials_returns_ticket(self):
        self.request.form.update(dict(ticket='ST-001-abc'))
        creds = self.plugin.extractCredentials(self.request)

        self.assertIn('ticket', creds)
        self.assertEqual('ST-001-abc', creds['ticket'])

    def test_extract_credentials_returns_service_url(self):
        self.request.form.update({'ticket': 'ST-001-abc'})
        creds = self.plugin.extractCredentials(self.request)

        self.assertIn('service_url', creds)
        self.assertEqual('http://nohost', creds['service_url'])

    def test_extract_credentials_redirects_to_service_url(self):
        self.request.form.update({'ticket': 'ST-001-abc'})
        self.plugin.extractCredentials(self.request)

        self.assertEqual(302, self.request.RESPONSE.status)
        self.assertDictContainsSubset({'location': 'http://nohost'},
                                      self.request.RESPONSE.headers)

    def test_extract_credentials_without_ticket_returns_none(self):
        creds = self.plugin.extractCredentials(self.request)

        self.assertEqual(None, creds)

    def test_extract_credentials_without_ticket_doesnt_redirect(self):
        self.plugin.extractCredentials(self.request)

        self.assertEqual(200, self.request.RESPONSE.status)
        self.assertNotIn('location', self.request.RESPONSE.headers)

    def test_service_url_has_ticket_stripped(self):
        params = OrderedDict(
            (('ticket', 'ST-001-abc'), ('param1', 'v1'), ('param2', 'v2')))
        self.request.form.update(params)
        self.request.environ['QUERY_STRING'] = urlencode(params)
        service_url = self.plugin._service_url(self.request)

        self.assertEqual('http://nohost?param1=v1&param2=v2', service_url)

    @patch('ftw.casauth.plugin.validate_ticket')
    def test_authenticate_credentials_succeeds_with_valid_credentials(self, mock_validate_ticket):
        mock_validate_ticket.return_value = TEST_USER_ID
        creds = {
            'extractor': self.plugin.getId(),
            'ticket': 'ST-001-abc',
            'service_url': 'http://127.0.0.1/'
        }
        self.plugin.REQUEST = self.request
        self.plugin.REQUEST.RESPONSE = self.request.response
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
        self.plugin.REQUEST = self.request
        self.plugin.REQUEST.RESPONSE = self.request.response
        ret = self.plugin.authenticateCredentials(creds)
        self.assertEqual(None, ret)

    @patch('ftw.casauth.plugin.validate_ticket')
    def test_sets_login_times_when_success(self, mock_validate_ticket):
        mtool = getToolByName(getSite(), 'portal_membership')

        mock_validate_ticket.return_value = TEST_USER_ID
        creds = {
            'extractor': self.plugin.getId(),
            'ticket': 'ST-001-abc',
            'service_url': 'http://127.0.0.1/'
        }
        self.plugin.REQUEST = self.request
        self.plugin.REQUEST.RESPONSE = self.request.response

        with freeze(datetime(2016, 2, 12, 16, 40)):
            userid, login = self.plugin.authenticateCredentials(creds)
            self.assertEqual(
                DateTime(),
                mtool.getMemberById(TEST_USER_ID).getProperty('login_time'))

    @patch('ftw.casauth.plugin.validate_ticket')
    def test_expires_clipboard_when_success(self, mock_validate_ticket):
        mock_validate_ticket.return_value = TEST_USER_ID
        creds = {
            'extractor': self.plugin.getId(),
            'ticket': 'ST-001-abc',
            'service_url': 'http://127.0.0.1/'
        }
        self.plugin.REQUEST = self.request
        self.plugin.REQUEST.RESPONSE = self.request.response
        self.plugin.REQUEST.RESPONSE.setCookie('__cp', ['file-1'], path='/')
        self.plugin.REQUEST['__cp'] = ['file-1']

        userid, login = self.plugin.authenticateCredentials(creds)

        cookie = self.plugin.REQUEST.RESPONSE.cookies.get('__cp')
        self.assertEqual('Wed, 31-Dec-97 23:59:59 GMT', cookie.get('expires'))
        self.assertEqual('deleted', cookie.get('value'))
