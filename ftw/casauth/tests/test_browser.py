from ftw.casauth.testing import FTW_CASAUTH_FUNCTIONAL_TESTING
from plone.app.testing import TEST_USER_NAME, TEST_USER_ID, TEST_USER_PASSWORD
from plone.app.testing import setRoles
from plone.testing.z2 import Browser

import unittest
import transaction


class TestCASAuthPlugin(unittest.TestCase):

    layer = FTW_CASAUTH_FUNCTIONAL_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        setRoles(self.portal, TEST_USER_ID, ['Manager'])
        transaction.commit()

    def browser(self, path):
        browser = Browser(self.portal)
        browser.addHeader('Authorization', 'Basic %s:%s' % (
            TEST_USER_NAME, TEST_USER_PASSWORD,))
        browser.open(self.portal.absolute_url() + path)
        return browser

    def test_install_plugin(self):
        browser = self.browser('/acl_users/manage_addProduct/ftw.casauth/manage_addCASAuthenticationPlugin')
        self.assertIn('<form action="addCASAuthenticationPlugin"', browser.contents)

        browser.getControl(name="id_").value = 'my_cas_plugin'
        browser.getControl(name="title").value = 'My CAS plugin'
        browser.getControl(name="cas_server_url").value = 'https://mycas'
        browser.getControl('Add').click()
        self.assertIn('my_cas_plugin', browser.contents)
        self.assertIn('My CAS plugin', browser.contents)

        transaction.begin()
        self.assertIn('my_cas_plugin', self.portal.acl_users.objectIds())

        plugin = self.portal.acl_users['my_cas_plugin']
        self.assertEquals('My CAS plugin', plugin.title)
        self.assertEquals('https://mycas', plugin.cas_server_url)

    def test_install_plugin_strips_trailing_slash_of_cas_server_url(self):
        browser = self.browser('/acl_users/manage_addProduct/ftw.casauth/manage_addCASAuthenticationPlugin')
        browser.getControl(name="id_").value = 'my_cas_plugin'
        browser.getControl(name="cas_server_url").value = 'https://mycas/'
        browser.getControl('Add').click()
        transaction.begin()
        self.assertEquals('https://mycas', self.portal.acl_users['my_cas_plugin'].cas_server_url)

    def test_config_updates_cas_server_url(self):
        browser = self.browser('/acl_users/cas_auth/manage_config')
        self.assertIn('<form action="manage_updateConfig"', browser.contents)

        browser.getControl(name="cas_server_url").value = 'https://anothercas'
        browser.getControl('Update').click()
        self.assertIn('Configuration updated', browser.contents)

        transaction.begin()
        self.assertEquals(
            'https://anothercas',
            self.portal.acl_users['cas_auth'].cas_server_url)

    def test_update_config_strips_trailing_slash_of_cas_server_url(self):
        browser = self.browser('/acl_users/cas_auth/manage_config')
        browser.getControl(name="cas_server_url").value = 'https://anothercas/'
        browser.getControl('Update').click()

        transaction.begin()
        self.assertEquals(
            'https://anothercas',
            self.portal.acl_users['cas_auth'].cas_server_url)
