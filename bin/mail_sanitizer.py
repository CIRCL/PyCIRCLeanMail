#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import glob
import os

from kittengroomer_email import KittenGroomerMail


def process_dir(path_in, path_out):
    for f in glob.glob(os.path.join(path_in, '*')):
        outfile = f.replace(path_in, path_out)
        try:
            t = KittenGroomerMail(open(f, 'rb').read())
        except:
            print('Failed to process', f)
            continue
        parsed_email = t.process_mail()
        if not os.path.exists(os.path.dirname(outfile)):
            os.makedirs(os.path.dirname(outfile))
        with open(outfile, 'wb') as out:
            out.write(parsed_email.as_bytes())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='KittenGroomer email processor', description="Sanitize emails")
    parser.add_argument('-s', '--source', required=True, type=str, help='Source directory')
    parser.add_argument('-d', '--destination', required=True, type=str, help='Destination directory')
    args = parser.parse_args()

    process_dir(args.source, args.destination)
