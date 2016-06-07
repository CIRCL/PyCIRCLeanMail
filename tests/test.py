#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os
import sys

from kittengroomer_email import KittenGroomerMail

if __name__ == '__main__':
    sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.curpath = os.getcwd()

    def test_basic(self):
        src = os.path.join(self.curpath, 'tests/mail_src')
        for path, subdirs, files in os.walk(src):
            for name in files:
                with open(os.path.join(path, name), 'rb') as f:
                    try:
                        t = KittenGroomerMail(f.read(), debug=True)
                        t.process_mail()
                    except:
                        print("Failed on ", name)
