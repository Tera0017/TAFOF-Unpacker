"""
Author:@Tera0017
"""
import os
import pefile
from ta505_gen_funcs import *


class TA505XLSExtractor:

    def __init__(self, fullpath):
        self.fullpath = fullpath
        self.filename = os.path.basename(fullpath)
        self.folder = fullpath.replace(self.filename, "")

    def gen_name(self, extr=''):
        return '{}TAFOF_XLS_bin_{}_{}.bin'.format(self.folder, extr, self.filename)

    @staticmethod
    def get_size(file_data):
        pe = pefile.PE(data=file_data)
        total_size = pe.OPTIONAL_HEADER.SizeOfHeaders
        for section in pe.sections:
            total_size += section.SizeOfRawData
        return total_size

    @staticmethod
    def get_osa(file_data):
        pe = pefile.PE(data=file_data)
        # 0x014C == x86, 0x8664 == x86-x64
        return 0x32 if pe.FILE_HEADER.Machine == 0x14c else 0x64

    def extract_binaries(self):
        extract = True
        xls_data = readFile(self.fullpath)
        st = xls_data.index('MZ')
        while extract:
            try:
                mz_data = xls_data[st:]
                total_size = self.get_size(mz_data)

                # first binary extracted usually its x86
                start = st
                end = start + total_size
                mz_data = xls_data[start:end]
                if self.get_osa(mz_data) == 0x32:
                    x86_path = self.gen_name('x86')
                    writeFile(x86_path, mz_data)
                else:
                    x64_path = self.gen_name('x64')
                    writeFile(x64_path, mz_data)

                # second binary x64
                start2 = end + xls_data[end:].index('MZ')
                mz_data2 = xls_data[start2:]
                total_size = self.get_size(mz_data2)
                end2 = end + xls_data[end:].index('MZ') + total_size
                mz_data2 = xls_data[end + xls_data[end:].index('MZ'): end2]
                if self.get_osa(mz_data2) == 0x64:
                    x64_path = self.gen_name('x64')
                    writeFile(x64_path, mz_data2)
                else:
                    x86_path = self.gen_name('x86')
                    writeFile(x86_path, mz_data)

                extract = False
            except pefile.PEFormatError:
                st = st + xls_data[st + 2:].index('MZ') + 2

        return x86_path, x64_path
