# -*- coding: utf-8 -*-
"""
Author:@Tera0017
"""
ERROR01 = 'Yara rules didn\'t match encoded code or more than 1. Make sure is packed with TA505 else DM hash @Tera0017'


def readFile(filename):
    return open(filename, 'rb').read()


def writeFile(filename, data):
    open(filename, 'wb').write(data)


def process_args():
    import argparse
    logo()
    parser = argparse.ArgumentParser(description='TA505 Unpacker')
    parser.add_argument('-f', '--file', type=str, help='File to decrypt.')
    parser.add_argument('-x', '--xls', action='store_true', help='Extract bin from XLS, default to False.')
    parser.add_argument('-u', '--upx', action='store_true', help='UPX  decryption to final payload, default to False.')
    return parser.parse_args()


def hexy(st):
    line = " ".join("{:02x}".format(ord(c)) for c in st).upper()
    n = 96
    return '\n'.join([line[i:i + n] for i in range(0, len(line), n)])


def rol(dword, n):
    n = n % 32
    return (dword << n | dword >> (32 - n)) & 0xFFFFFFFF


def fix_dword(enc_data):
    for i in range(0, len(enc_data) % 4):
        enc_data += '\x00'
    return enc_data


def split_per(line, n):
    return [line[i:i + n] for i in range(0, len(line), n)]


def message(msg):
    print '|--> {}'.format(msg)


def logo():
    print u'''▄▄▄█████▓▄▄▄       █████▒█████   █████▒    █    ██ ███▄    █ ██▓███  ▄████▄  ██ ▄█▀██▀███  
▓  ██▒ ▓▒████▄   ▓██   ▒██▒  ██▓██   ▒     ██  ▓██▒██ ▀█   █▓██░  ██▒██▀ ▀█  ██▄█▒▓██ ▒ ██▒
▒ ▓██░ ▒▒██  ▀█▄ ▒████ ▒██░  ██▒████ ░    ▓██  ▒██▓██  ▀█ ██▓██░ ██▓▒▓█    ▄▓███▄░▓██ ░▄█ ▒
░ ▓██▓ ░░██▄▄▄▄██░▓█▒  ▒██   ██░▓█▒  ░    ▓▓█  ░██▓██▒  ▐▌██▒██▄█▓▒ ▒▓▓▄ ▄██▓██ █▄▒██▀▀█▄  
  ▒██▒ ░ ▓█   ▓██░▒█░  ░ ████▓▒░▒█░       ▒▒█████▓▒██░   ▓██▒██▒ ░  ▒ ▓███▀ ▒██▒ █░██▓ ▒██▒
  ▒ ░░   ▒▒   ▓▒█░▒ ░  ░ ▒░▒░▒░ ▒ ░       ░▒▓▒ ▒ ▒░ ▒░   ▒ ▒▒▓▒░ ░  ░ ░▒ ▒  ▒ ▒▒ ▓░ ▒▓ ░▒▓░
    ░     ▒   ▒▒ ░░      ░ ▒ ▒░ ░         ░░▒░ ░ ░░ ░░   ░ ▒░▒ ░      ░  ▒  ░ ░▒ ▒░ ░▒ ░ ▒░
  ░       ░   ▒   ░ ░  ░ ░ ░ ▒  ░ ░        ░░░ ░ ░   ░   ░ ░░░      ░       ░ ░░ ░  ░░   ░ 
              ░  ░         ░ ░               ░             ░        ░ ░     ░  ░     ░     
                                                                    ░                      
|--> TA505 Unpacker.'''
