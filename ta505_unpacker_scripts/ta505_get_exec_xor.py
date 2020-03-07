"""
Author:@Tera0017
"""
import yara
import struct
import pefile
from ta505_gen_funcs import *

rules_x86 = {
    # Finds encoded code PART 1 + its length then can find exec code and xor key (strict rule)
    '$code1': '{68 F4 0B 00 00 68 [4] 8B ?? [4] 5? E8}',
    # // Finds encoded code PART 1 + its length then can find exec code and xor key (wider rule)
    '$code2': '{68 [4] 68 [4] 8B 85 [4] 50 E8}',
    # // Getting exec code PART I + size
    '$code3': '{C7 45 ?? [4] C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 EB [10] 81 [2] 84 03 00 00}',
    # // Getting directly code and size
    '$code4': '{A3 [4] C7 05 [8] C7 05 [8] (8?| A1)}',
    # // Getting directly code and size
    '$code5': '{89 [2] C7 45 ?? [4] C7 45 ?? [4] 8? 15 [4] 8?}',
    # // check which code decrypts code (which usually is the same as exec layer 1)
    '$code6': '{(E8 03 00 00 89 [2] C1 [2] (FF| FE) FF FF 07| C1 45 ?? 07 8?)}',
    # Find encoded code PART 1 + length the can find exec code and xor key
    '$code7': '{F4 0B 00 00 [2] 8? [11] 8? ?? [4] 8? ?? EB}',
    # 21.2.20 update
    '$code8': '{81 [2] ?? ?? 00 00 7? [10] 8A ?? ?? ?? ?? ?? 8? 0? EB}',
    # get size strict
    '$code9': '{C7 4? ?? ?? ?? 03 00}',
    # get size open
    '$code10': '{C7 4? ?? ?? ?? 0? 00}',

}

rules_x64 = {
    '$code1': '{48 C7 (84| 44) 24 ([4]| ??) ?? 4? 03 00 (C7 84| C7 44| E8)}',
    '$code2': '{8? [4] 00 00 C1 ?? 07 89}',
    '$code3': '{48 C7 (84| 44) 24 ([4]| ??) ?? ?? ?? 00 (C7 84 24| C7 44 24| E8)}',
    '$code4': '{FF 15 [2] 00 00 [4-40] 48 8D 05 [4-40] 48 C7 (84| 44) 24 ([4]| ??) ?? ?? ?? 00}'
}

tmp_rule = '''
rule match_rule
{
    strings:
        %s = %s
    condition:
        any of them
}'''.strip()


class TA505Packer:
    def __init__(self, file_data, osa, layer_rule):
        self.file_data = file_data
        self.layer1_encryption = ''
        self.pe = pefile.PE(data=self.file_data, fast_load=True)
        self.osa = osa
        self.rules = {'x86': rules_x86, 'x64': rules_x64}[self.osa]
        self.layer_rule = layer_rule

    def match_rule(self, rule, data=None):
        data = self.file_data if data is None else data
        myrules = tmp_rule % (rule, self.rules[rule])
        yararules = yara.compile(source=myrules)
        return yararules.match(data=data)

    def get_layer1_encyption(self):
        if len(self.match_rule(self.layer_rule)) == 1:
            self.layer1_encryption = 'rol_7'
        else:
            self.layer1_encryption = 'rol_4'

    def pickup_exact_code(self, temp_code):
        enc_exec_code = ''
        ps_add = 2
        if (self.osa == 'x86' and self.layer1_encryption == 'rol_4') or self.osa == 'x64':
            mod_val = 2
            if self.osa == 'x64':
                ps_add = 1
        else:
            mod_val = 3
        pos_counter = 0
        counter = 0
        while pos_counter < len(temp_code):
            if not counter % mod_val:
                pos_counter += ps_add
            enc_exec_code += temp_code[pos_counter]
            pos_counter += 1
            counter += 1
        return enc_exec_code

    def get_exec_xor(self):
        xor_key, exec_addr, exec_size = self.find_exec_xor_addr_size()
        if not exec_addr and not xor_key:
            return ['Error', ERROR01, None]

        message('Encrypted Layer One size: {}'.format(hex(exec_size).upper()))
        self.get_layer1_encyption()

        # For getandgodll mod is 2, for silence/miner/azorult its 3 (x86)
        encoded_exec_code = self.pickup_exact_code(self.pe.get_data(rva=exec_addr, length=exec_size))
        encoded_exec_code = fix_dword(encoded_exec_code)

        return [encoded_exec_code, xor_key, self.layer1_encryption]


class TA505x86Packer(TA505Packer):

    def __init__(self, file_data):
        TA505Packer.__init__(self, file_data, 'x86', '$code6')

    def fix_address(self, address):
        return address - self.pe.OPTIONAL_HEADER.ImageBase

    def get_xor_key(self, address):
        try:
            return struct.unpack('I', self.pe.get_data(rva=self.fix_address(address), length=4))[0]
        except struct.error as err:
            message('ERROR possibly corrupted binary')
            raise struct.error(err)

    def find_exec_xor_addr_size(self):
        # finds the encoded code PART I and from that gets xor and executable code (Getandgo)
        for rule in ['$code1', '$code2']:
            match = self.match_rule(rule)
            if match and len(match) == 1:
                opcodes = match[0].strings[0][2]
                size = struct.unpack('I', opcodes[1:1+4])[0]
                encoded_code_addr = struct.unpack('I', opcodes[6:6+4])[0]
                xor_key_addr = encoded_code_addr + size
                executable_addr = xor_key_addr + 4
                xor_key = self.get_xor_key(xor_key_addr)
                exec_size = self.get_enc_size(executable_addr)
                executable_addr = self.fix_address(executable_addr)
                return xor_key, executable_addr, exec_size
        # gets encrypted code and adding its size get the exe enc code + xor key (rest Silence/Azorult/Miner)
        for rule in ['$code3']:
            match = self.match_rule(rule)
            if match and len(match) == 1:
                opcodes = match[0].strings[0][2]
                encoded_code_addr = struct.unpack('I', opcodes[3:3 + 4])[0]
                executable_addr = encoded_code_addr + 0x384 * 4 + 4
                xor_key_addr = executable_addr - 4
                xor_key = self.get_xor_key(xor_key_addr)
                exec_size = self.get_enc_size(executable_addr)
                executable_addr = self.fix_address(executable_addr)
                return xor_key, executable_addr, exec_size
        # gets directly the encrypted and size
        for rule in ['$code4']:
            match = self.match_rule(rule)
            if match and len(match) == 1:
                opcodes = match[0].strings[0][2]
                executable_addr = struct.unpack('I', opcodes[11: 11 + 4])[0]
                xor_key_addr = executable_addr - 4
                xor_key = self.get_xor_key(xor_key_addr)
                exec_size = self.get_enc_size(executable_addr)
                executable_addr = self.fix_address(executable_addr)
                return xor_key, executable_addr, exec_size

        # gets directly the encrypted and size
        for rule in ['$code5']:
            match = self.match_rule(rule)
            if match and len(match) == 1:
                opcodes = match[0].strings[0][2]
                executable_addr = struct.unpack('I', opcodes[6: 6 + 4])[0]
                xor_key_addr = executable_addr - 4
                xor_key = self.get_xor_key(xor_key_addr)
                exec_size = self.get_enc_size(executable_addr)
                executable_addr = self.fix_address(executable_addr)
                return xor_key, executable_addr, exec_size

        # gets code after update :P
        for rule in ['$code7']:
            match = self.match_rule(rule)
            if match and len(match) == 1:
                opcodes = match[0].strings[0][2]
                encoded_code_addr = struct.unpack('I', opcodes[20: 20 + 4])[0]
                size = struct.unpack('I', opcodes[0: 4])[0]
                xor_key_addr = encoded_code_addr + size
                executable_addr = xor_key_addr + 4
                xor_key = self.get_xor_key(xor_key_addr)
                exec_size = self.get_enc_size(executable_addr)
                executable_addr = self.fix_address(executable_addr)
                return xor_key, executable_addr, exec_size

        # gets code after update 21.2.20
        for rule in ['$code8']:
            match = self.match_rule(rule)
            if match and len(match) == 1:
                opcodes = match[0].strings[0][2]
                xor_key_addr = struct.unpack('I', opcodes[20: 20 + 4])[0] + struct.unpack('I', opcodes[3: 3 + 4])[0]
                executable_addr = xor_key_addr + 4
                xor_key = self.get_xor_key(xor_key_addr)
                exec_size = self.get_enc_size(executable_addr)
                executable_addr = self.fix_address(executable_addr)
                return xor_key, executable_addr, exec_size

        # gets size
        for rule in ['$code9', '$code10']:
            matches = self.match_rule(rule)
            for match in matches:
                try:
                    opcodes = match.strings[0][2]
                    rule_addr = match.strings[0][0]
                    exec_size = struct.unpack('I', opcodes[3: 3 + 4])[0]
                    search = struct.unpack('B', opcodes[2: 2 + 1])[0] + 4
                    search = '\x89\x45' + struct.pack('B', search)
                    data = self.pe.get_data(rule_addr, 50)
                    id = data.index(search)
                    data = data[7:id]
                    search = '\xA1'
                    id = data.index(search) + 1
                    xor_key_addr = struct.unpack('I', data[id: id + 4])[0]
                    xor_key = self.get_xor_key(xor_key_addr)
                    executable_addr = self.fix_address(xor_key_addr + 4)
                    return xor_key, executable_addr, exec_size
                except:
                    pass

        return None, None, None

    def get_enc_size(self, executable_address):
        exec_addr_op = struct.pack('I', executable_address)
        # finds address opcodes in executable, and after is the size
        exec_addr_op_usage = self.file_data.index(exec_addr_op)
        exec_addr_op_usage += self.file_data[exec_addr_op_usage:exec_addr_op_usage + 20].index('\xC7')
        spl_op = self.file_data[exec_addr_op_usage:exec_addr_op_usage + 2]
        # gets last for bytes of next instruction (size)
        size_data = self.file_data[exec_addr_op_usage: exec_addr_op_usage + 20].split(spl_op)[1]
        # C7 (05|85) -> 4
        pos = 1 if spl_op == '\xC7\x45' else 4
        return struct.unpack('I', size_data[pos: pos + 4])[0]

    def get_second_key(self):
        xor_key_addr, exec_addr, exec_size = self.find_exec_xor_addr_size()
        exec_addr += self.pe.OPTIONAL_HEADER.ImageBase - 1000
        for i in range(0, 4000):
            exec_addr -= 1
            op_codes = struct.pack('I', exec_addr)
            try:
                encoded_addr = self.file_data.index(op_codes)
            except ValueError:
                continue

            mv1 = self.pe.get_data(rva=encoded_addr - 3, length=2)
            mv2 = self.pe.get_data(rva=encoded_addr - 6, length=2)
            mv3 = self.pe.get_data(rva=encoded_addr - 2, length=1)
            mv3 = int(mv3.encode('hex'), 16)
            if mv1 in ['\xC7\x45', '\xC7\x05'] or mv2 == '\xC7\x85' or mv3 in range(0x88, 0x8f):
                exec_addr -= self.pe.OPTIONAL_HEADER.ImageBase
                return struct.unpack('I', self.pe.get_data(rva=exec_addr - 4, length=4))[0]
        raise Exception('Tried 2 XOR Keys None worked')


class TA505x64Packer(TA505Packer):

    def __init__(self, file_data):
        TA505Packer.__init__(self, file_data, 'x64', '$code2')

    def temp_rule(self, search, data=None):
        self.rules['$temp_rule'] = '{%s}' % search
        return self.match_rule('$temp_rule', data)

    @staticmethod
    def test_if_valid_exec_code(s):
        s = ''.join(s.split('\x00'))
        if is_ascii(s):
            return False
        return True

    def find_exec_addr(self, rule_addr):
        rule_addr = self.pe.get_rva_from_offset(rule_addr)
        data_search = self.pe.get_data(rva=rule_addr - 500, length=500)
        data_search = '\x00\x00' + data_search
        matches = data_search.split('\x48\x8D\x05')
        for i in range(1, len(matches)):
            temp_search = '\x48\x8D\x05' + matches[i][:4]
            temp_search = temp_search.encode('hex')
            temp_search = ' '.join([temp_search[i:i + 2] for i in range(0, len(temp_search), 2)]).upper()
            match = self.temp_rule(temp_search)
            rule_match_addr = match[0].strings[0][0]
            opcodes = match[0].strings[0][2]
            exec_addr = struct.unpack('I', opcodes[3: 3 + 4])[0]
            try:
                temp_data = self.pe.get_data(rva=exec_addr + self.pe.get_rva_from_offset(rule_match_addr) + 7, length=6)
            except pefile.PEFormatError:
                continue
            if self.test_if_valid_exec_code(temp_data):
                return exec_addr + self.pe.get_rva_from_offset(rule_match_addr) + 7

    def find_xor_key(self, stack_opcodes, idx, rl_addr):
        rl_addr = self.pe.get_rva_from_offset(rl_addr)
        data = self.pe.get_data(rva=rl_addr, length=1000)
        xor_stack = stack_opcodes & 0xFF
        xor_stack += 8
        xor_stack = struct.pack('>B', xor_stack)
        for ops, ind in [('\xC7\x44\x24', 4), ('\xC7\x84\x24', 4 + 3)]:
            try:
                idxx = data.index(ops + xor_stack)
                return struct.unpack('I', data[idxx + ind: idxx + ind + 4])[0]
            except Exception:
                pass

        xor_stack = struct.pack('>I', stack_opcodes + 8).encode('hex')
        xor_stack = ' '.join([xor_stack[i:i + 2] for i in range(0, len(xor_stack), 2)]).upper()
        rp = 'C7 44 24' if idx == 0 else 'C7 84 24'
        match = self.temp_rule(xor_stack.replace(rp, 'C7 44 24') + ' ??' * 4 + ' 8?')
        if match:
            opcodes = match[0].strings[0][2]
        else:
            idx = 3
            rp = 'C7 44 24'
            match = self.temp_rule(xor_stack.replace(rp, 'C7 84 24') + ' ??' * 7 + ' (C7| 8B| 87)')
            if not match:
                raise Exception(ERROR01)
            opcodes = match[0].strings[0][2]
        return struct.unpack('I', opcodes[4 + idx: 4 + idx + 4])[0]

    def legit_values(self, ex_addr, ex_size):
        try:
            self.pe.get_data(rva=ex_addr, length=ex_size)
            return True
        except:
            return False

    def find_exec_xor_addr_size(self):
        # finds the encoded code PART I and from that gets xor and executable code (Getandgo)
        for rule in ['$code1', '$code3']:
            matches = self.match_rule(rule)
            for match in matches:
                ind = 0
                try:
                    rule_match_addr = match.strings[0][0]
                    opcodes = match.strings[0][2]
                    if '\x48\xC7\x84\x24' in opcodes:
                        # C7 84 24 matched
                        ind = 3
                    executable_size = struct.unpack('I', opcodes[ind + 5: ind + 5 + 4])[0]
                    xor_key = self.find_xor_key(struct.unpack('>I', opcodes[1: 1 + 4])[0], ind, rule_match_addr)
                    executable_addr = self.find_exec_addr(rule_match_addr)
                    if not self.legit_values(executable_addr, executable_size):
                        continue
                    return xor_key, executable_addr, executable_size
                except:
                    pass

        for rule in ['$code4']:
            matches = self.match_rule(rule)
            for match in matches:
                ind = 0
                ind_find = '\x48\xC7\x44\x24'
                opcodes = match.strings[0][2]
                rule_match_addr = match.strings[0][0]
                if '\x48\xC7\x84\x24' in opcodes:
                    # C7 84 24 matched
                    ind_find = '\x48\xC7\x84\x24'
                    ind = 3
                rule_match_addr = rule_match_addr + len(opcodes[:opcodes.index(ind_find)])
                opcodes = opcodes[opcodes.index(ind_find):]
                executable_size = struct.unpack('I', opcodes[ind + 5: ind + 5 + 4])[0]
                xor_key = self.find_xor_key(struct.unpack('>I', opcodes[1: 1 + 4])[0], ind, rule_match_addr)
                executable_addr = self.find_exec_addr(rule_match_addr)
                if not self.legit_values(executable_addr, executable_size):
                    continue
                return xor_key, executable_addr, executable_size

        return None, None, None
