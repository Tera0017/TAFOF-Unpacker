"""
Author:@Tera0017
TA505Packer static unpacker
"""
import os
import subprocess
from ta505_unpacker.ta505_gen_funcs import *
from ta505_unpacker.ta505_get_exec_xor import TA505Packer
from ta505_unpacker.ta505_decode_code import TA505Decoder
from ta505_unpacker.ta505_xls_bin_extractor import TA505XLSExtractor


class TA505Unpacker:

    def __init__(self, arguments):
        self.fullpath = arguments.file
        self.filename = os.path.basename(arguments.file)
        self.folder = arguments.file.replace(self.filename, "")
        self.upx = arguments.upx
        self.xls = arguments.xls

    def gen_name(self, extr=''):
        return '{}TA505{}_unpacker_{}'.format(self.folder, extr, self.filename)

    def unpack_upx(self, unp_name):
        FNULL = open(os.devnull, 'w')
        return subprocess.call(["upx", "-d", unp_name, "-o", self.gen_name('_UPX')], stdout=FNULL, stderr=subprocess.STDOUT)

    def decrypt(self):
        ta505pacer = TA505Packer(readFile(self.fullpath))
        message('Loaded Packed Exe Data: {}'.format(self.filename))

        encoded_exec_code, xor_key, layer1_enc = ta505pacer.get_exec_xor()
        if encoded_exec_code == 'Error':
            message('[ERROR] {}'.format(xor_key))
            return False
        message('Found Encrypted Code')
        message('Found XOR KEY: {}'.format(hex(xor_key).upper()))
        message('Layer One encryption: {}'.format(layer1_enc))

        ta505decoder = TA505Decoder(encoded_exec_code, xor_key, layer1_enc)
        exec_code = ta505decoder.decode_code()

        # unpacked TA505 packer file
        unpacked_name = self.gen_name()
        writeFile(unpacked_name, exec_code)
        message('Unpacked TA505: {}'.format(unpacked_name))

        if self.upx:
            # usually its also packed with UPX, needs to have UPX in the system
            # 0: 'unpacked', 1: 'already_exists', '2': 'did not unpack'
            if self.unpack_upx(unpacked_name) != 2:
                message('Unpacked TA505 UPX: {}'.format(self.gen_name('_UPX')))
            message('Unpacked Successfully')
        else:
            message('*Possibly needs to be unpacked with UPX as well try -u/--upx/-uf')

    def unpack(self):
        if self.xls:
            message('Extracting binaries from XLS.')
            ta505_xls_extractor = TA505XLSExtractor(self.fullpath)
            for extracted_bin in ta505_xls_extractor.extract_binaries():
                if 'x86' in extracted_bin:
                    self.fullpath = extracted_bin
                    self.filename = os.path.basename(extracted_bin)
                message('Extracted TA505 binary from XLS: {}'.format(extracted_bin))
        message('Starting TA505 Unpacker')
        self.decrypt()


if __name__ == '__main__':
    ta505_unpacker = TA505Unpacker(process_args())
    ta505_unpacker.unpack()

