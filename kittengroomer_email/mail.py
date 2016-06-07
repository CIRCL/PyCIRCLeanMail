#!/usr/bin/env python
# -*- coding: utf-8 -*-

from email.parser import BytesParser
from email.utils import make_msgid
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.header import decode_header

from .helpers import FileBaseMem
from .helpers import KittenGroomerMailBase

import mimetypes
import olefile
import zipfile
import officedissector
import tarfile
import lzma
import bz2
import gzip
import os
from pdfid.pdfid import PDFiD, cPDFiD
from io import BytesIO

# Prepare application/<subtype>
mimes_ooxml = ['vnd.openxmlformats-officedocument.']
mimes_office = ['msword', 'vnd.ms-']
mimes_libreoffice = ['vnd.oasis.opendocument']
mimes_rtf = ['rtf', 'richtext']
mimes_pdf = ['pdf', 'postscript']
mimes_xml = ['xml']
mimes_ms = ['dosexec']
mimes_compressed = ['zip', 'rar', 'bzip2', 'lzip', 'lzma', 'lzop',
                    'xz', 'compress', 'gzip', 'tar']
mimes_data = ['octet-stream']
mimes_force_text = ['pgp-signature']

# Prepare image/<subtype>
mimes_exif = ['image/jpeg', 'image/tiff']
mimes_png = ['image/png']

# Aliases
aliases = {
    # Win executables
    'application/x-msdos-program': 'application/x-dosexec',
    'application/x-dosexec': 'application/x-msdos-program',
    # Other apps with confusing mimetypes
    'application/rtf': 'text/rtf',
    'application/pgp-signature': 'text/plain',
}
aliases_ext = {'.asc': '.sig'}

# Sometimes, mimetypes.guess_type is giving unexpected results, such as for the .tar.gz files:
# In [12]: mimetypes.guess_type('toot.tar.gz', strict=False)
# Out[12]: ('application/x-tar', 'gzip')
# It works as expected if you do mimetypes.guess_type('application/gzip', strict=False)
propertype = {'.gz': 'application/gzip', '.tgz': 'application/gzip', '.asc': 'application/pgp-signature'}

# Commonly used malicious extensions
# Sources: http://www.howtogeek.com/137270/50-file-extensions-that-are-potentially-dangerous-on-windows/
# https://github.com/wiregit/wirecode/blob/master/components/core-settings/src/main/java/org/limewire/core/settings/FilterSettings.java
mal_ext = (
    # Applications
    ".exe", ".pif", ".application", ".gadget", ".msi", ".msp", ".com", ".scr",
    ".hta", ".cpl", ".msc", ".jar",
    # Scripts
    ".bat", ".cmd", ".vb", ".vbs", ".vbe", ".js", ".jse", ".ws", ".wsf",
    ".wsc", ".wsh", ".ps1", ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2",
    ".msh", ".msh1", ".msh2", ".mshxml", ".msh1xml", ".msh2xml",
    # Shortcuts
    ".scf", ".lnk", ".inf",
    # Other
    ".reg", ".dll",
    # Office macro (OOXML with macro enabled)
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam",
    ".ppsm", ".sldm",
    # banned from wirecode
    ".asf", ".asx", ".au", ".htm", ".html", ".mht", ".vbs",
    ".wax", ".wm", ".wma", ".wmd", ".wmv", ".wmx", ".wmz", ".wvx",
)


class File(FileBaseMem):

    def __init__(self, file_obj, orig_filename):
        ''' Init file object, set the mimetype '''
        super(File, self).__init__(file_obj, orig_filename)

        self.is_recursive = False
        if not self.has_mimetype():
            # No mimetype, should not happen.
            self.make_dangerous()

        if not self.has_extension():
            self.make_dangerous()

        if self.extension in mal_ext:
            self.log_details.update({'malicious_extension': self.extension})
            self.make_dangerous()

        if self.is_dangerous():
            return

        self.log_details.update({'maintype': self.main_type,
                                 'subtype': self.sub_type,
                                 'extension': self.extension})

        # Check correlation known extension => actual mime type
        if propertype.get(self.extension) is not None:
            expected_mimetype = propertype.get(self.extension)
        else:
            expected_mimetype, encoding = mimetypes.guess_type(self.orig_filename, strict=False)
            if aliases.get(expected_mimetype) is not None:
                expected_mimetype = aliases.get(expected_mimetype)

        is_known_extension = self.extension in mimetypes.types_map.keys()
        if is_known_extension and expected_mimetype != self.mimetype:
            self.log_details.update({'expected_mimetype': expected_mimetype})
            self.make_dangerous()

        # check correlation actual mime type => known extensions
        if aliases.get(self.mimetype) is not None:
            mimetype = aliases.get(self.mimetype)
        else:
            mimetype = self.mimetype

        expected_extensions = set(mimetypes.guess_all_extensions(mimetype, strict=False))
        if expected_extensions:
            extra_ext = [aliases_ext.get(ext) for ext in expected_extensions if aliases_ext.get(ext, None)]
            expected_extensions.update(extra_ext)
            if len(self.extension) > 0 and self.extension not in expected_extensions:
                self.log_details.update({'expected_extensions': list(expected_extensions)})
                # self.make_dangerous()
        else:
            # there are no known extensions associated to this mimetype.
            pass


class KittenGroomerMail(KittenGroomerMailBase):

    def __init__(self, raw_email, max_recursive=2, debug=False):
        super(KittenGroomerMail, self).__init__(raw_email, debug)

        self.recursive = 0
        self.is_archive = False
        self.max_recursive = max_recursive

        subtypes_apps = [
            (mimes_office, self._winoffice),
            (mimes_ooxml, self._ooxml),
            (mimes_rtf, self.text),
            (mimes_libreoffice, self._libreoffice),
            (mimes_pdf, self._pdf),
            (mimes_xml, self.text),
            (mimes_ms, self._executables),
            (mimes_compressed, self._archive),
            (mimes_data, self._binary_app),
            (mimes_force_text, self.text),
        ]
        self.subtypes_application = self._init_subtypes_application(subtypes_apps)

        self.mime_processing_options = {
            'text': self.text,
            'audio': self.audio,
            'image': self.image,
            'video': self.video,
            'application': self.application,
            'example': self.example,
            'message': self.message,
            'model': self.model,
            'multipart': self.multipart,
            'inode': self.inode,
        }

    def _init_subtypes_application(self, subtypes_application):
        '''
            Create the Dict to pick the right function based on the sub mime type
        '''
        to_return = {}
        for list_subtypes, fct in subtypes_application:
            for st in list_subtypes:
                to_return[st] = fct
        return to_return

    #######################

    def inode(self):
        ''' Usually empty file. No reason (?) to copy it on the dest key'''
        if self.cur_attachment.is_symlink():
            self.cur_attachment.log_string += 'Symlink to {}'.format(self.log_details['symlink'])
        else:
            self.cur_attachment.log_string += 'Inode file'

    def unknown(self):
        ''' This main type is unknown, that should not happen '''
        self.cur_attachment.log_string += 'Unknown file'

    def example(self):
        '''Used in examples, should never be returned by libmagic'''
        self.cur_attachment.log_string += 'Example file'

    def multipart(self):
        '''Used in web apps, should never be returned by libmagic'''
        self.cur_attachment.log_string += 'Multipart file'

    #######################

    def model(self):
        '''Way to process model file'''
        self.cur_attachment.log_string += 'Model file'
        self.cur_attachment.make_dangerous()

    #######################

    def message(self):
        '''Way to process message file'''
        self.cur_attachment.log_string += 'Message file'
        self.recursive += 1
        self.cur_attachment = self.process_mail(self.cur_attachment)
        self.recursive -= 1

    # ##### Converted ######
    def text(self):
        for r in mimes_rtf:
            if r in self.cur_attachment.sub_type:
                self.cur_attachment.log_string += 'Rich Text file'
                # TODO: need a way to convert it to plain text
                self.cur_attachment.force_ext('.txt')
                return
        for o in mimes_ooxml:
            if o in self.cur_attachment.sub_type:
                self.cur_attachment.log_string += 'OOXML File'
                self._ooxml()
                return
        self.cur_attachment.log_string += 'Text file'
        self.cur_attachment.force_ext('.txt')

    def application(self):
        ''' Everything can be there, using the subtype to decide '''
        for subtype, fct in self.subtypes_application.items():
            if subtype in self.cur_attachment.sub_type:
                self.cur_attachment.log_string += 'Application file'
                fct()
                return
        self.cur_attachment.log_string += 'Unknown Application file'
        self._unknown_app()

    def _executables(self):
        '''Way to process executable file'''
        self.cur_attachment.add_log_details('processing_type', 'executable')
        self.cur_attachment.make_dangerous()

    def _winoffice(self):
        # FIXME: oletools isn't compatible with python3, using olefile only
        self.cur_attachment.add_log_details('processing_type', 'WinOffice')
        # Try as if it is a valid document
        try:
            ole = olefile.OleFileIO(self.cur_attachment.file_obj, raise_defects=olefile.DEFECT_INCORRECT)
        except:
            self.cur_attachment.add_log_details('not_parsable', True)
            self.cur_attachment.make_dangerous()
        if ole.parsing_issues:
            self.cur_attachment.add_log_details('parsing_issues', True)
            self.cur_attachment.make_dangerous()
        else:
            if ole.exists('macros/vba') or ole.exists('Macros') \
                    or ole.exists('_VBA_PROJECT_CUR') or ole.exists('VBA'):
                self.cur_attachment.add_log_details('macro', True)
                self.cur_attachment.make_dangerous()

    def _ooxml(self):
        self.cur_attachment.add_log_details('processing_type', 'ooxml')
        try:
            doc = officedissector.doc.Document(pseudofile=self.cur_attachment.file_obj,
                                               filename=self.cur_attachment.orig_filename)
        except Exception:
            # Invalid file
            self.cur_attachment.make_dangerous()
            return
        # There are probably other potentially malicious features:
        # fonts, custom props, custom XML
        if doc.is_macro_enabled or len(doc.features.macros) > 0:
            self.cur_attachment.add_log_details('macro', True)
            self.cur_attachment.make_dangerous()
        if len(doc.features.embedded_controls) > 0:
            self.cur_attachment.add_log_details('activex', True)
            self.cur_attachment.make_dangerous()
        if len(doc.features.embedded_objects) > 0:
            # Exploited by CVE-2014-4114 (OLE)
            self.cur_attachment.add_log_details('embedded_obj', True)
            self.cur_attachment.make_dangerous()
        if len(doc.features.embedded_packages) > 0:
            self.cur_attachment.add_log_details('embedded_pack', True)
            self.cur_attachment.make_dangerous()

    def _libreoffice(self):
        self.cur_attachment.add_log_details('processing_type', 'libreoffice')
        # As long as there ar no way to do a sanity check on the files => dangerous
        try:
            lodoc = zipfile.ZipFile(self.cur_attachment.file_obj, 'r')
        except:
            self.cur_attachment.add_log_details('invalid', True)
            self.cur_attachment.make_dangerous()
        for f in lodoc.infolist():
            fname = f.filename.lower()
            if fname.startswith('script') or fname.startswith('basic') or \
                    fname.startswith('object') or fname.endswith('.bin'):
                self.cur_attachment.add_log_details('macro', True)
                self.cur_attachment.make_dangerous()

    def _pdf(self):
        '''Way to process PDF file'''
        self.cur_attachment.add_log_details('processing_type', 'pdf')
        # Required to avoid having the file closed by PDFiD
        tmp_obj = BytesIO(self.cur_attachment.file_obj.getvalue())
        xmlDoc = PDFiD(tmp_obj)
        oPDFiD = cPDFiD(xmlDoc, True)
        # TODO: other keywords?
        if oPDFiD.encrypt.count > 0:
            self.cur_attachment.add_log_details('encrypted', True)
            self.cur_attachment.make_dangerous()
        if oPDFiD.js.count > 0 or oPDFiD.javascript.count > 0:
            self.cur_attachment.add_log_details('javascript', True)
            self.cur_attachment.make_dangerous()
        if oPDFiD.aa.count > 0 or oPDFiD.openaction.count > 0:
            self.cur_attachment.add_log_details('openaction', True)
            self.cur_attachment.make_dangerous()
        if oPDFiD.richmedia.count > 0:
            self.cur_attachment.add_log_details('flash', True)
            self.cur_attachment.make_dangerous()
        if oPDFiD.launch.count > 0:
            self.cur_attachment.add_log_details('launch', True)
            self.cur_attachment.make_dangerous()

    def _zip(self):
        '''Zip processor'''
        archive = zipfile.ZipFile(self.cur_attachment.file_obj)
        loc_attach = []
        for subfile in archive.namelist():
            try:
                cur_file = File(archive.open(subfile).read(), subfile)
                self.process_payload(cur_file)
                loc_attach.append(self.cur_attachment)
            except Exception:
                self.cur_attachment.make_dangerous()
                return [self.cur_attachment]
        return loc_attach

    def _lzma(self):
        '''LZMA processor'''
        try:
            archive = lzma.decompress(self.cur_attachment.file_obj.read())
            new_fn, ext = os.path.splitext(self.cur_attachment.orig_filename)
            cur_file = File(archive, new_fn)
            self.process_payload(cur_file)
        except:
            self.cur_attachment.make_dangerous()
        return self.cur_attachment

    def _gzip(self):
        '''GZip processor'''
        try:
            archive = gzip.decompress(self.cur_attachment.file_obj.read())
            new_fn, ext = os.path.splitext(self.cur_attachment.orig_filename)
            cur_file = File(archive, new_fn)
            self.process_payload(cur_file)
        except:
            self.cur_attachment.make_dangerous()
        return self.cur_attachment

    def _bzip(self):
        '''BZip2 processor'''
        try:
            archive = bz2.decompress(self.cur_attachment.file_obj.read())
            new_fn, ext = os.path.splitext(self.cur_attachment.orig_filename)
            cur_file = File(archive, new_fn)
            self.process_payload(cur_file)
        except:
            self.cur_attachment.make_dangerous()
        return self.cur_attachment

    def _tar(self):
        '''Tar processor'''
        archive = tarfile.open(mode='r:*', fileobj=self.cur_attachment.file_obj)
        loc_attach = []
        for subfile in archive.getmembers():
            try:
                cur_file = File(archive.extractfile(subfile).read(), subfile.name)
                self.process_payload(cur_file)
                loc_attach.append(self.cur_attachment)
            except Exception:
                self.cur_attachment.make_dangerous()
                return self.cur_attachment
        return loc_attach

    def _archive(self):
        '''Way to process Archive'''
        # NOTE: currently only supports gzip, bz2, lzma, zip and tar
        self.cur_attachment.add_log_details('processing_type', 'archive')
        if self.is_archive:
            self.cur_attachment.add_log_details('recursive archive', True)
            self.cur_attachment.make_dangerous()
            self.is_archive = False
            return
        self.is_archive = True
        # It is highly plausible that lzma, gzip and bzip are in fact also tarfiles
        # Trying that first...
        if 'lzma' in self.cur_attachment.mimetype:
            try:
                self.cur_attachment = self._tar()
            except:
                self.cur_attachment = self._lzma()
        elif 'gzip' in self.cur_attachment.mimetype:
            try:
                self.cur_attachment = self._tar()
            except:
                self.cur_attachment = self._gzip()
        elif 'bzip' in self.cur_attachment.mimetype:
            try:
                self.cur_attachment = self._tar()
            except:
                self.cur_attachment = self._bzip()
        elif 'zip' in self.cur_attachment.mimetype:
            self.cur_attachment = self._zip()
        elif 'tar' in self.cur_attachment.mimetype:
            self.cur_attachment = self._tar()
        else:
            self.cur_attachment.add_log_details('unsupported archive', True)
            self.cur_attachment.make_dangerous()
        self.is_archive = False

    def _unknown_app(self):
        '''Way to process an unknown file'''
        self.cur_attachment.make_unknown()

    def _binary_app(self):
        '''Way to process an unknown binary file'''
        self.cur_attachment.make_binary()

    # ##### Not converted, checking the mime type ######
    def audio(self):
        '''Way to process an audio file'''
        self.cur_attachment.log_string += 'Audio file'
        self._media_processing()

    def image(self):
        '''Way to process an image'''
        self.cur_attachment.log_string += 'Image file'
        self._media_processing()
        self.cur_attachment.add_log_details('processing_type', 'image')

    def video(self):
        '''Way to process a video'''
        self.cur_attachment.log_string += 'Video file'
        self._media_processing()

    def _media_processing(self):
        '''Generic way to process all the media files'''
        self.cur_attachment.add_log_details('processing_type', 'media')

    #######################

    def reassemble_mail(self, parsed_email, to_keep, attachments):
        original_msgid = parsed_email.get_all('Message-ID')
        try:
            parsed_email.replace_header('Message-ID', make_msgid())
        except:
            parsed_email.add_header('Message-ID', make_msgid())
        if to_keep:
            if parsed_email.is_multipart():
                parsed_email.set_payload([to_keep[0]])
            else:
                parsed_email.set_payload(to_keep[0])
                return parsed_email
        else:
            info_msg = MIMEText('Empty Message', _subtype='plain', _charset='utf-8')
            parsed_email.set_payload([info_msg])
        for k in to_keep[1:]:
            parsed_email.attach(k)
        info = 'The attachments of this mail have been sanitzed.\nOriginal Message-ID: {}'.format(original_msgid)
        info_msg = MIMEText(info, _subtype='plain', _charset='utf-8')
        info_msg.add_header('Content-Disposition', 'attachment', filename='Sanitized.txt')
        parsed_email.attach(info_msg)
        for f in attachments:
            msg = self.pack_attachment(f)
            for m in msg:
                parsed_email.attach(m)
        return parsed_email

    def pack_attachment(self, attachment):
        print(attachment.log_details)
        processing_info = '{}'.format(attachment.log_details)
        processing_info_msg = MIMEText(processing_info, _subtype='plain', _charset='utf-8')
        processing_info_msg.add_header('Content-Disposition', 'attachment', filename='{}.log'.format(attachment.orig_filename))
        msg = MIMEBase(attachment.main_type, attachment.sub_type)
        msg.set_payload(attachment.file_obj.getvalue())
        encoders.encode_base64(msg)
        msg.add_header('Content-Disposition', 'attachment', filename=attachment.final_filename)
        return [processing_info_msg, msg]

    def split_email(self, raw_email):
        parsed_email = BytesParser().parsebytes(raw_email)
        to_keep = []
        attachments = []
        if parsed_email.is_multipart():
            for p in parsed_email.get_payload():
                if p.get_filename():
                    filename = decode_header(p.get_filename())
                    if filename[0][1]:
                        filename = filename[0][0].decode(filename[0][1])
                    else:
                        filename = filename[0][0]
                    attachments.append(File(p.get_payload(decode=True), filename))
                else:
                    to_keep.append(p)
        else:
            to_keep.append(parsed_email.get_payload())
        return to_keep, attachments, parsed_email

    def process_payload(self, payload):
        self.cur_attachment = payload
        self.log_name.info('Processing {} ({}/{})', self.cur_attachment.orig_filename,
                           self.cur_attachment.main_type, self.cur_attachment.sub_type)
        if not self.cur_attachment.is_dangerous():
            self.mime_processing_options.get(self.cur_attachment.main_type, self.unknown)()

    def process_mail(self, raw_email=None):
        if raw_email is None:
            raw_email = self.raw_email

        if self.recursive > 0:
            self._print_log()

        if self.recursive >= self.max_recursive:
            self.cur_attachment.make_dangerous()
            self.cur_attachment.add_log_details('To many recursive mails', True)
            self.log_name.warning('ARCHIVE BOMB.')
            self.log_name.warning('The content of the archive contains recursively other archives.')
            self.log_name.warning('This is a bad sign so the archive is not extracted to the destination key.')
            return self.pack_attachment(self.cur_attachment)
        else:
            to_keep, attachments, parsed_email = self.split_email(raw_email)
            final_attach = set(attachments)
            for f in attachments:
                self.process_payload(f)
                # At this point, self.cur_attachment can be a list (if the original one was an archive)
                if isinstance(self.cur_attachment, list):
                    final_attach.discard(f)
                    final_attach.update(self.cur_attachment)
                else:
                    final_attach.discard(f)
                    final_attach.add(self.cur_attachment)
            parsed_email = self.reassemble_mail(parsed_email, to_keep, final_attach)
            return parsed_email
