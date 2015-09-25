.. contents::

Introduction
============

This product provides a PAS plugin for authentication of users in Plone
against a CAS (Central Autentication Server).

It currently supports CAS 2.0 and CAS 3.0 protocols.


Installation
============

Add ``ftw.casauth`` to the list of eggs in your buildout, run buildout and
restart your instance.

In the ZMI navigate to your ``acl_users`` folder and add a CAS Authentication Plugin.
You must provide the url of your CAS server, e.g. https://cas.server.net. Then
activate the Challenge, Extraction and Authentication functionality.


Links
=====

- Github: https://github.com/4teamwork/ftw.casauth
- Issues: https://github.com/4teamwork/ftw.casauth/issues


Copyright
=========

This package is copyright by `4teamwork <http://www.4teamwork.ch/>`_.

``ftw.casauth`` is licensed under GNU General Public License, version 2.
