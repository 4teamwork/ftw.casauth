from datetime import datetime
from DateTime import DateTime
from ftw.casauth.testing import FTW_CASAUTH_INTEGRATION_TESTING
from ftw.testbrowser import browsing
from ftw.testing import freeze
from mock import patch
from plone import api
from plone.app.testing import TEST_USER_ID

import json
import unittest


class TestCASLogin(unittest.TestCase):

    layer = FTW_CASAUTH_INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer['portal']

    @browsing
    def test_missing_ticket_returns_400(self, browser):
        with browser.expect_http_error(code=400, reason='Bad Request'):
            browser.open(
                self.portal.absolute_url() + '/@caslogin',
                method='POST',
                headers={'Accept': 'application/json'},
            )
        self.assertEqual(browser.status_code, 400)
        self.assertEqual(
            browser.json[u'error'][u'type'], u'Missing service ticket')

    @browsing
    def test_missing_plugin_returns_501(self, browser):
        self.portal.acl_users._delOb('cas_auth')
        with browser.expect_http_error(code=501, reason='Not Implemented'):
            browser.open(
                self.portal.absolute_url() + '/@caslogin',
                data=json.dumps({
                    "ticket": "12345",
                }),
                method='POST',
                headers={'Accept': 'application/json',
                         'Content-Type': 'application/json'},
            )
        self.assertEqual(browser.status_code, 501)
        self.assertEqual(
            browser.json[u'error'][u'message'],
            u'CAS/JWT authentication plugin not installed.')

    @browsing
    def test_valid_ticket_returns_jwt_token(self, browser):
        with patch('ftw.casauth.restapi.caslogin.validate_ticket') as mock:
            mock.return_value = TEST_USER_ID
            browser.open(
                self.portal.absolute_url() + '/@caslogin',
                data=json.dumps({
                    "ticket": "12345",
                }),
                method='POST',
                headers={'Accept': 'application/json',
                         'Content-Type': 'application/json'},
            )
        self.assertEqual(browser.status_code, 200)
        self.assertIn(u'token', browser.json)

    @browsing
    def test_accepts_service_url_from_body(self, browser):
        with patch('ftw.casauth.restapi.caslogin.validate_ticket') as mock:
            mock.return_value = TEST_USER_ID
            browser.open(
                self.portal.absolute_url() + '/@caslogin',
                data=json.dumps({
                    "ticket": "12345",
                    "service": "http://myhost/#test",
                }),
                method='POST',
                headers={'Accept': 'application/json',
                         'Content-Type': 'application/json'},
            )
        self.assertEqual(browser.status_code, 200)
        self.assertIn(u'token', browser.json)
        mock.assert_called_with(
            u'12345', 'https://cas.domain.net', u'http://myhost/#test')

    @browsing
    def test_sets_login_times_when_success(self, browser):
        with patch('ftw.casauth.restapi.caslogin.validate_ticket') as mock:
            mock.return_value = TEST_USER_ID
            with freeze(datetime(2016, 2, 12, 16, 40)):
                browser.open(
                    self.portal.absolute_url() + '/@caslogin',
                    data=json.dumps({
                        "ticket": "12345",
                        "service": "http://myhost/#test",
                    }),
                    method='POST',
                    headers={'Accept': 'application/json',
                             'Content-Type': 'application/json'},
                )
                mtool = api.portal.get_tool('portal_membership')
                self.assertEqual(DateTime(),
                                 mtool.getMemberById(TEST_USER_ID).getProperty('login_time'))
