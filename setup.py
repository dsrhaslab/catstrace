# -*- coding: utf-8 -*-

# Learn more: https://github.com/kennethreitz/setup.py

from setuptools import setup, find_packages

EXCLUDE_FROM_PACKAGES = ['catstrace.bin']

with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='catstrace',
    version='0.1.0',
    description='',
    author='Tânia Esteves',
    author_email='tania.c.araujo@inesctec.pt',
    url='https://github.com/taniaesteves/catstrace',
    license=license,
    packages=find_packages(exclude=EXCLUDE_FROM_PACKAGES),
    install_requires=[
        'ujson',
        'python-dotenv',
        'sortedcontainers',
        'psutil',
        'progressbar2',
        'hlwy-lsh',
        'setproctitle',
        'simplejson',
        'lark'
    ],
    test_suite='nose.collector',
    tests_require=['nose'],
    include_package_data=True,
    scripts=['catstrace/bin/CatStrace.py'],
    entry_points={'console_scripts': ['catstrace=catstrace.CatStrace:main']}
)