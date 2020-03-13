# MIT License
#
# Copyright (c) 2020 yeggor
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

import json
import os
import time

import click

import lief

__author__ = "yeggor"
__version__ = "1.0.0"

# reads configuration data
with open("config.json", "rb") as cfile:
    config = json.load(cfile)

# gets configuration data
EFI_MODULES = config["EFI_MODULES"]
assert os.path.isdir(EFI_MODULES)
ANALYSER_PATH = config["ANALYSER_PATH"]
IDA_PATH = '"{}"'.format(config["IDA_PATH"])
IDA64_PATH = '"{}"'.format(config["IDA64_PATH"])

# lief machine type constants
LIEF_IA32 = "ARCH.i386"
LIEF_X64 = "ARCH.x86_64"


class dbgs_analyser:
    def __init__(self, dirname):
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

    def _show_item(self, item):
        return "current module: {}".format(item)

    def _handle_all(self):
        with click.progressbar(
                self.files,
                length=len(self.files),
                bar_template=click.style("%(label)s  %(bar)s | %(info)s",
                                         fg="cyan"),
                label="Modules analysis",
                item_show_func=self._show_item,
        ) as bar:
            for elf in bar:
                _, ext = os.path.splitext(elf)
                if ext != ".debug":
                    continue
                binary = lief.parse(elf)
                if str(binary.header.machine_type) == LIEF_IA32:
                    ida_path = IDA_PATH
                if str(binary.header.machine_type) == LIEF_X64:
                    ida_path = IDA64_PATH
                cmd_line = " ".join(
                    [ida_path, "-c -A -S{}".format(ANALYSER_PATH), elf])
                if not os.system(cmd_line):
                    msg = "[-] Error during {module} module processing\n\t{hint}".format(
                        module=elf,
                        hint=
                        "check your config.json file or move analyse_and_exit.py file to idc directory",
                    )
                    exit(msg)

    @classmethod
    def do(cls, dirname):
        cls = cls(dirname)
        cls._get_files(cls.root_dir)
        return cls._handle_all()


if __name__ == "__main__":
    start_time = time.time()
    dbgs_analyser.do(EFI_MODULES)
    print('[time] {}'.format(time.time() - start_time))
