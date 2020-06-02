from setuptools import setup, find_packages
import os
import sys

version = '1.3.0'

tests_require = [
    'plone.api',
    'plone.app.testing',
    'plone.restapi',
    'mock',
    'ftw.testbrowser',
    'ftw.testing',
]

install_requires = [
    'Plone',
    'setuptools',
]
python_major_version = sys.version_info[0]
python_minor_version = sys.version_info[1]
python_micro_version = sys.version_info[2]
if python_major_version == 2:
    if python_minor_version < 5:
        install_requires.append('hashlib')
    if python_minor_version < 6:
        install_requires.append('ssl')
    if not (python_minor_version == 7 and python_micro_version >= 9):
        install_requires.append('backports.ssl_match_hostname')

setup(
    name='ftw.casauth',
    version=version,
    description='Plone PAS plugin for authentication against CAS.',
    long_description=(open('README.rst').read() + '\n' +
                      open(os.path.join('docs', 'HISTORY.txt')).read()),
    classifiers=[
        'Framework :: Plone',
        'Framework :: Plone :: 4.1',
        'Framework :: Plone :: 4.2',
        'Framework :: Plone :: 4.3',
        'Framework :: Plone :: 5.1',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],

    keywords='',
    author='Thomas Buchberger',
    author_email='mailto:t.buchberger@4teamwork.ch',
    url='https://github.com/4teamwork/ftw.casauth',
    license='GPL2',

    packages=find_packages(exclude=['ez_setup']),
    namespace_packages=['ftw'],
    include_package_data=True,
    zip_safe=False,

    install_requires=install_requires,
    tests_require=tests_require,
    extras_require=dict(tests=tests_require),
    entry_points="""
    # -*- Entry points: -*-
    [z3c.autoinclude.plugin]
    target = plone
    """,
)
