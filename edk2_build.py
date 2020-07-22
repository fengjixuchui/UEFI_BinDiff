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

# Use this file from Developer Command Prompt for VS

import os
import pathlib
import shutil

PACKAGES = [
    'CryptoPkg', 'EmulatorPkg', 'FatPkg', 'FmpDevicePkg', 'NetworkPkg',
    'SecurityPkg', 'SignedCapsulePkg', 'UefiCpuPkg', 'EmbeddedPkg',
    'IntelFsp2WrapperPkg', 'MdeModulePkg', 'PcAtChipsetPkg', 'ShellPkg',
    'SourceLevelDebugPkg', 'UnitTestFrameworkPkg'
]
OUT_DIR = 'efi_modules'


def call(command: list):
    return os.system(' '.join(command))


def build():
    # build efi modules
    os.chdir('edk2')
    call(['edksetup.bat', 'Rebuild'])
    for package in PACKAGES:
        call([
            'build', '-a', 'X64', '-p',
            '{platform}/{platform}.dsc'.format(platform=package), '-b',
            'DEBUG', '-t', 'VS2019'
        ])
    # collect efi modules
    os.chdir('..')
    if not os.path.isdir(OUT_DIR):
        os.mkdir(OUT_DIR)
    for src in pathlib.Path(os.path.join('edk2', 'Build')).rglob('*.efi'):
        _, efi_name = os.path.split(src)
        dst = os.path.join(OUT_DIR, efi_name)
        shutil.copy(src, dst)
    print('Done: check \'efi_modules\' directory')


if __name__ == '__main__':
    build()
