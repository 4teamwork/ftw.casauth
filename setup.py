from setuptools import setup, find_packages
import os

version = '1.7.2.dev0'

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
    'six >= 1.12.0',
]


setup(
    name='ftw.casauth',
    version=version,
    description='Plone PAS plugin for authentication against CAS.',
    long_description=(open('README.rst').read() + '\n' +
                      open(os.path.join('docs', 'HISTORY.txt')).read()),
    classifiers=[
        'Framework :: Plone',
        'Framework :: Plone :: 4.3',
        'Framework :: Plone :: 5.1',
        'Framework :: Plone :: 5.2',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.8',
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
