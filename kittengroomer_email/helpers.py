#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import magic
from twiggy import outputs, filters, log, formats, emitters, levels

from io import BytesIO
from io import StringIO


class KittenGroomerError(Exception):
    def __init__(self, message):
        '''
            Base KittenGroomer exception handler.
        '''
        super(KittenGroomerError, self).__init__(message)
        self.message = message


class ImplementationRequired(KittenGroomerError):
    '''
        Implementation required error
    '''
    pass


class FileBaseMem(object):

    def __init__(self, file_obj, orig_filename=None):
        self.file_obj = BytesIO(file_obj)
        self.orig_filename = orig_filename
        if self.orig_filename:
            self.final_filename = self.orig_filename
        else:
            self.final_filename = 'unknownfile.bin'
        self.log_details = {'origFilename': self.orig_filename}
        self.log_string = ''
        if self.orig_filename:
            a, self.extension = os.path.splitext(self.orig_filename)
        else:
            self.extension = None

        try:
            mt = magic.from_buffer(self.file_obj.getvalue(), mime=True)
        except UnicodeEncodeError as e:
            # FIXME: The encoding of the file is broken (possibly UTF-16)
            mt = ''
            self.log_details.update({'UnicodeError': e})
        try:
            self.mimetype = mt.decode("utf-8")
        except:
            self.mimetype = mt

        if self.mimetype and '/' in self.mimetype:
            self.main_type, self.sub_type = self.mimetype.split('/')
        else:
            self.main_type = ''
            self.sub_type = ''

    def has_mimetype(self):
        if not self.main_type or not self.sub_type:
            self.log_details.update({'broken_mime': True})
            return False
        return True

    def has_extension(self):
        if not self.extension:
            self.log_details.update({'no_extension': True})
            return False
        return True

    def is_dangerous(self):
        if self.log_details.get('dangerous'):
            return True
        return False

    def add_log_details(self, key, value):
        '''
            Add an entry in the log dictionary
        '''
        self.log_details[key] = value

    def make_dangerous(self):
        '''
            This file should be considered as dangerous and never run.
            Prepending and appending DANGEROUS to the destination
            file name avoid double-click of death
        '''
        if self.is_dangerous():
            # Already marked as dangerous, do nothing
            return
        self.log_details['dangerous'] = True
        self.final_filename = 'DANGEROUS_{}_DANGEROUS'.format(self.final_filename)

    def make_unknown(self):
        '''
            This file has an unknown type and it was not possible to take
            a decision. The user will have to decide what to do.
            Prepending UNKNOWN
        '''
        if self.is_dangerous() or self.log_details.get('binary'):
            # Already marked as dangerous or binary, do nothing
            return
        self.log_details['unknown'] = True
        self.final_filename = 'UNKNOWN_{}'.format(self.final_filename)

    def make_binary(self):
        '''
            This file is a binary, and should probably not be run.
            Appending .bin avoir double click of death but the user
            will have to decide by itself.
        '''
        if self.is_dangerous():
            # Already marked as dangerous, do nothing
            return
        self.log_details['binary'] = True
        self.final_filename = '{}.bin'.format(self.final_filename)

    def force_ext(self, ext):
        if not self.final_filename.endswith(ext):
            self.log_details['force_ext'] = True
            self.final_filename += ext


class KittenGroomerMailBase(object):

    def __init__(self, raw_email, debug=False):
        '''
            Setup the base options of the copy/convert setup
        '''
        self.raw_email = raw_email
        self.log_processing = StringIO()
        self.log_content = StringIO()
        self.tree(self.raw_email)

        twiggy_out = outputs.StreamOutput(formats.shell_format, stream=self.log_processing)
        emitters['*'] = filters.Emitter(levels.DEBUG, True, twiggy_out)

        self.log_name = log.name('files')

        self.cur_attachment = None

        self.debug = debug
        if self.debug:
            if not os.path.exists('debug_logs'):
                os.makedirs('debug_logs')
            self.log_debug_err = os.path.join('debug_logs', 'debug_stderr.log')
            self.log_debug_out = os.path.join('debug_logs', 'debug_stdout.log')
        else:
            self.log_debug_err = os.devnull
            self.log_debug_out = os.devnull

    def tree(self, raw_email):
        # TODO: Tree-like function for the email
        return

    def process_mail(self, raw_email=None):
        '''
            Main function doing the work, you have to implement it yourself.
        '''
        raise ImplementationRequired('You have to implement process_mail.')
