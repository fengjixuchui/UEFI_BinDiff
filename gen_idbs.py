#!/usr/bin/env python3.7

################################################################################
# MIT License
#
# Copyright (c) 2018-2020 yeggor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
################################################################################

import json
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

import click
from elftools.elf.elffile import ELFFile
from tqdm import tqdm

__author__ = 'yeggor'
__version__ = '1.1.0'

# reads configuration data
with open('config.json', 'rb') as cfile:
    config = json.load(cfile)

# configuration data
ANALYSER_PATH = config['ANALYSER_PATH']
IDA_PATH = '"{}"'.format(config['IDA_PATH'])
IDA64_PATH = '"{}"'.format(config['IDA64_PATH'])

# PE constants
PE_OFFSET = 0x3c
IMAGE_FILE_MACHINE_IA64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014c


def get_num_le(bytearr):
    num_le = 0
    for i in range(len(bytearr)):
        num_le += bytearr[i] * pow(256, i)
    return num_le


def get_machine_type_pe(module_path):
    with open(module_path, 'rb') as module:
        data = module.read()
    PE_POINTER = get_num_le(data[PE_OFFSET:PE_OFFSET + 1:])
    FH_POINTER = PE_POINTER + 4
    machine_type = data[FH_POINTER:FH_POINTER + 2:]
    type_value = get_num_le(machine_type)
    if type_value == IMAGE_FILE_MACHINE_IA64:
        return 'x64'
    if type_value == IMAGE_FILE_MACHINE_I386:
        return 'x64'
    return None


def get_machine_type_elf(module_path):
    with open(module_path, 'rb') as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            return None
    return elffile.get_machine_arch()


def analyse_module(module_path, scr_path, idat, idat64):
    # get machine type
    with open(module_path, 'rb') as f:
        header = f.read(2)
    if header == b'\x4d\x5a':
        arch = get_machine_type_pe(module_path)
    elif header == b'\x7f\x45':
        arch = get_machine_type_elf(module_path)
    else:
        return False
    # get idat executable
    if arch == 'x86':
        idat_path = idat
    elif arch == 'x64':
        idat_path = idat64
    else:
        return False
    cmd = ' '.join([idat_path, '-c -A -S{}'.format(scr_path), module_path])
    # analyse module in batch mode
    os.system(cmd)
    if not (os.path.isfile('{}.i64'.format(module_path))
            or os.path.isfile('{}.idb'.format(module_path))):
        print('[ERROR] module: {}'.format(module_path))
        exit()
    return True


def analyse_all(files, scr_path, max_workers, idat, idat64):
    # check first module
    analyse_module(files[0], scr_path, idat, idat64)
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(analyse_module, module, scr_path, idat, idat64)
            for module in files[1:]
        ]
        params = {
            'total': len(futures),
            'unit': 'module',
            'unit_scale': True,
            'leave': True
        }
        for _ in tqdm(as_completed(futures), **params):
            pass


class dbgs_analyser:
    def __init__(self, dirname, workers):
        self.files = []
        self.root_dir = dirname

    def _get_files(self, dirname):
        items = os.listdir(dirname)
        for item in items:
            new_item = os.path.join(dirname, item)
            if os.path.isfile(new_item):
                self.files.append(new_item)
            if os.path.isdir(new_item):
                self._get_files(new_item)

    @classmethod
    def do(cls, dirname, workers):
        cls = cls(dirname, workers)
        cls._get_files(cls.root_dir)
        analyse_all(cls.files, ANALYSER_PATH, workers, IDA_PATH, IDA64_PATH)


@click.command()
@click.argument('modules_dir')
@click.option('-w',
              '--workers',
              help='Number of workers (8 by default).',
              type=int)
def main(modules_dir, workers):
    """Get idb and i64 files from modules in specified directory"""
    if not os.path.isdir(modules_dir):
        print('[ERROR] check modules directory')
        return False
    if not workers:
        workers = 8
    start_time = time.time()
    dbgs_analyser.do(modules_dir, workers)
    print('[time] {} s.'.format(round(time.time() - start_time, 3)))
    return True


# pylint: disable=no-value-for-parameter
if __name__ == '__main__':
    main()
