"""
Author:@Tera0017
"""
import json
import struct
from ta505_gen_funcs import *


class TA505Decoder:
    def __init__(self, encoded, xor_key, layer_1_enc, osa):
        self.layer_1_enc = layer_1_enc
        self.encoded = [struct.unpack('I', encoded[i:i+4])[0] for i in range(0, len(encoded), 4)]
        self.xor_key = xor_key
        self.encoded_layer1 = ''
        self.decrypted_exec = []
        self.osa = osa
        self.config = {'mem_in_counter': 1, 'mem_out_counter': 1,
                       'value': '', 'rev_counter': 0,
                       'stop_flag': 0,
                       'var_14': 0, 'var_10': 0, 'var_8_loop': 4, 'var_C': -1, 'var_4': 0, 'loop_var_4': 1}

    def printstate(self, msg=''):
        print '--------------------{}--------------------'.format(msg)
        print json.dumps(self.config, indent=4, sort_keys=True)
        print hexy(self.decrypted_exec)

    def conf_val_rev(self):
        self.config['rev_counter'] -= 1
        if self.config['rev_counter'] == -1:
            self.config['value'] = ord(self.encoded_layer1[self.config['mem_in_counter']])
            self.config['mem_in_counter'] += 1
            self.config['rev_counter'] = 7
        ret_val = (self.config['value'] >> 7) & 1
        self.config['value'] = (self.config['value'] << 1) & 0xFFFFFFFF
        return ret_val

    def loop_conf_val_rev(self):
        self.config['loop_var_4'] = 1
        while True:
            temp1 = self.conf_val_rev()
            self.config['loop_var_4'] = temp1 + self.config['loop_var_4'] * 2
            if not self.conf_val_rev():
                break
        return self.config['loop_var_4']

    def decode_code(self):
        self.decode_layer1()
        message("Decrypted TA505 First Layer")
        self.decode_layer2()
        return ''.join(self.decrypted_exec)

    def decode_layer1(self):
        z = 0
        if self.layer_1_enc == 'rol_4':
            for i in range(0, len(self.encoded)):
                dword_enc = self.encoded[i]
                dword_enc ^= self.xor_key
                dword_enc = (rol(dword_enc, 4) + 0x77777778) & 0xFFFFFFFF
                self.encoded_layer1 += struct.pack("I", dword_enc)

        elif self.layer_1_enc == 'rol_7':
            # layer_1 encryption is with rol_7
            for i in range(0, len(self.encoded)):
                if self.osa == 'x86':
                    z = i
                dword_enc = self.encoded[i] - z
                dword_enc ^= self.xor_key
                dword_enc = (rol(dword_enc, 7) ^ self.xor_key)
                self.encoded_layer1 += struct.pack("I", dword_enc)

    def decode_layer2(self):
        self.decrypted_exec = list(self.encoded_layer1[0])
        while self.config['stop_flag'] == 0:
            if self.conf_val_rev():
                if self.conf_val_rev():
                    if self.conf_val_rev():
                        self.config['var_14'] = 0
                        for self.config['var_8_loop'] in range(4, 0, -1):
                            ret_val = self.conf_val_rev()
                            self.config['var_14'] = ret_val + (self.config['var_14'] * 2) & 0xFFFFFFFF
                        self.config['var_8_loop'] = 0
                        if self.config['var_14'] == 0:
                            # loc_A20
                            self.config['mem_out_counter'] += 1
                            self.decrypted_exec += ['\x00']
                        else:
                            self.decrypted_exec += [self.decrypted_exec[self.config['mem_out_counter'] - self.config['var_14']]]
                            self.config['mem_out_counter'] += 1
                        self.config['var_4'] = 0
                    else:
                        # loc_A8B
                        self.config['var_14'] = ord(self.encoded_layer1[self.config['mem_in_counter']])
                        self.config['mem_in_counter'] += 1
                        self.config['var_10'] = (self.config['var_14'] & 1) + 2
                        self.config['var_14'] >>= 1
                        if self.config['var_14']:
                            # loc_A6B
                            while self.config['var_10']:
                                self.decrypted_exec += [self.decrypted_exec[self.config['mem_out_counter'] - self.config['var_14']]]
                                self.config['mem_out_counter'] += 1
                                self.config['var_10'] -= 1
                            self.config['var_C'] = self.config['var_14']
                        else:
                            # loc_A8B
                            self.config['stop_flag'] = 1

                        self.config['var_C'] = self.config['var_14']
                        self.config['var_4'] = 1
                else:
                    self.config['var_14'] = self.loop_conf_val_rev()
                    if self.config['var_4'] or self.config['var_14'] != 2:
                        if self.config['var_4'] != 0:
                            self.config['var_14'] -= 2
                        else:
                            self.config['var_14'] -= 3
                        # loc_B1C
                        self.config['var_14'] = (self.config['var_14'] << 8) & 0xFFFFFFFF
                        self.config['var_14'] += ord(self.encoded_layer1[self.config['mem_in_counter']])
                        self.config['mem_in_counter'] += 1

                        self.config['var_10'] = self.loop_conf_val_rev()
                        if self.config['var_14'] >= 0x7D00:
                            self.config['var_10'] += 1

                        if self.config['var_14'] >= 0x500:
                            self.config['var_10'] += 1

                        if self.config['var_14'] < 0x80:
                            self.config['var_10'] += 2

                        while self.config['var_10']:
                            self.decrypted_exec += [self.decrypted_exec[self.config['mem_out_counter'] - self.config['var_14']]]
                            self.config['mem_out_counter'] += 1
                            self.config['var_10'] -= 1
                        self.config['var_C'] = self.config['var_14']
                    else:
                        self.config['var_14'] = self.config['var_C']
                        ret_val = self.loop_conf_val_rev()
                        self.config['var_10'] = ret_val
                        while self.config['var_10']:
                            # loc_ADF
                            self.decrypted_exec += [self.decrypted_exec[self.config['mem_out_counter'] - self.config['var_14']]]
                            self.config['mem_out_counter'] += 1
                            self.config['var_10'] -= 1
                    self.config['var_4'] = 1
            else:
                self.decrypted_exec += [self.encoded_layer1[self.config['mem_in_counter']]]
                self.config['mem_out_counter'] += 1
                self.config['mem_in_counter'] += 1
                self.config['var_4'] = 0


class TA505x86Decoder(TA505Decoder):

    def __init__(self, encoded, xor_key, layer_1_enc):
        TA505Decoder.__init__(self, encoded, xor_key, layer_1_enc, 'x86')


class TA505x64Decoder(TA505Decoder):

    def __init__(self, encoded, xor_key, layer_1_enc):
        TA505Decoder.__init__(self, encoded, xor_key, layer_1_enc, 'x64')
