#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import setup

setup(
    name='kittengroomer_email',
    version='1.0.0',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/CIRCL/PyCIRCLeanMail',
    description='Standalone CIRCLean/KittenGroomer code to sanitize emails.',
    packages=['kittengroomer_email'],
    scripts=['bin/mail_sanitizer.py'],
    test_suite="tests",
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Security'
    ]
)
