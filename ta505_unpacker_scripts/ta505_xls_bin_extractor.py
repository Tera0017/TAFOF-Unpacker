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

    def extract_binaries(self):
        extract = True
        xls_data = readfile(self.fullpath)
        st = xls_data[2:].index('MZ') + 2
        counter = 0
        paths = []
        while extract:
            try:
                mz_data = xls_data[st:]
                total_size = self.get_size(mz_data)

                # first binary extracted usually its x86
                start = st
                end = start + total_size
                mz_data = xls_data[start:end]
                counter += 1
                if get_osa(file_data=mz_data) == 0x32:
                    path = self.gen_name('x86_{}'.format(counter))
                else:
                    path = self.gen_name('x64_{}'.format(counter))
                writefile(path, mz_data)
                paths.append(path)
                st = st + xls_data[st + 2:].index('MZ') + 2
            except pefile.PEFormatError:
                try:
                    st = st + xls_data[st + 2:].index('MZ') + 2
                except ValueError:
                    break
            except ValueError:
                message('Extracted samples {}'.format(counter))
                break
        if len(paths) != 2:
            message('Number of samples extracted from XLS {}'.format(len(paths)))
        return paths
