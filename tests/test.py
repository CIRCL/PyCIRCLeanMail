#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os
import sys
from io import BytesIO

from kittengroomer_email import KittenGroomerMail

if __name__ == '__main__':
    sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.curpath = os.getcwd()

    def test_basic(self):
        src = os.path.join(self.curpath, 'tests/mail_src')
        dst = os.path.join(self.curpath, 'tests/mail_dst')
        if not os.path.exists(dst):
            os.makedirs(dst)
        for path, subdirs, files in os.walk(src):
            for name in files:
                full_path = os.path.join(path, name)
                with open(full_path, 'rb') as f:
                    t = KittenGroomerMail(f.read(), debug=True)
                    m = t.process_mail()
                    content = BytesIO(m.as_bytes())
                    with open(full_path.replace(src, dst), 'wb') as z:
                        z.write(content.getvalue())
