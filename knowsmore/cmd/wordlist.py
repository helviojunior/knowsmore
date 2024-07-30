import datetime
import errno
import itertools
import math
import os
import re
import shutil
import sqlite3
import time
from argparse import _ArgumentGroup, Namespace
from binascii import hexlify
import random
import string
from pathlib import Path

from clint.textui import progress
from functools import reduce
import numpy as np

from knowsmore.cmdbase import CmdBase
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.knowsmoredb import KnowsMoreDB
from knowsmore.util.logger import Logger
from knowsmore.util.tools import Tools

LEETS1 = {"a": "aA@49\u00e1\u00c1\u00e0\u00c0\u00c2\u00c3\u00c4\u00c5\u00e2\u00e3\u00e4\u00e5", "b": "bB8", "c": "cC\u00e7\u00c7", "d": "dD", "e": "eE32\u00c8\u00c9\u00ca\u00cb\u00e8\u00e9\u00ea\u00eb", "f": "fF", "g": "gG96", "h": "hH#", "i": "iI!1\u00cc\u00cd\u00ce\u00cf\u00ec\u00ed\u00ee\u00ef", "j": "jJ", "k": "kK", "l": "lL!1", "m": "mM", "n": "nN\u00f1\u00d1", "o": "oO*04\u00d2\u00d3\u00d4\u00d5\u00d6\u00f2\u00f3\u00f4\u00f5\u00f6", "p": "pP", "q": "qQ", "r": "rR", "s": "sS5$", "t": "tT7+", "u": "uU\u00d9\u00da\u00db\u00dc\u00f9\u00fa\u00fb\u00fc", "v": "vV", "w": "wW", "x": "xX", "y": "yY\u00dd\u00fd", "z": "zZ2", "0": "0", "1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7", "8": "8", "9": "9"}
LEETS2 = {"a":"a","b":"b","c":"c","d":"d","e":"e","f":"f","g":"g","h":"h","i":"i","j":"j","k":"k","l":"l","m":"m","n":"n","o":"o","p":"p","q":"q","r":"r","s":"s","t":"t","u":"u","v":"v","w":"w","x":"x","y":"y","z":"z","A":"A","B":"B","C":"C","D":"D","E":"E","F":"F","G":"G","H":"H","I":"I","J":"J","K":"K","L":"L","M":"M","N":"N","O":"O","P":"P","Q":"Q","R":"R","S":"S","T":"T","U":"U","V":"V","W":"W","X":"X","Y":"Y","Z":"Z","0":"0","1":"1","2":"2","3":"3","4":"4","5":"5","6":"6","7":"7","8":"8","9":"9"}
LEETS3 = {"a": "aA@4", "b": "bB8", "c": "cC", "d": "dD", "e": "eE3", "f": "fF", "g": "gG96", "h": "hH#", "i": "iI!1", "j": "jJ", "k": "kK", "l": "lL!1", "m": "mM", "n": "nN", "o": "oO0*", "p": "pP", "q": "qQ", "r": "rR", "s": "sS5$", "t": "tT7+", "u": "uU", "v": "vV", "w": "wW", "x": "xX", "y": "yY", "z": "zZ2", "0": "0", "1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7", "8": "8", "9": "9"}
SPECIAL = ["@", "#", "!", ".", "-", ",", "$", "%", "*", "+", "/", "\\", "<", ">", "=", "&"]
COMMON = ["123", "1234", "12345", "123456"]

class WordList(CmdBase):
    db = None
    name = ''
    min_size = 1
    max_size = 32
    level = 3
    padding = False
    no_leets = False
    small = False
    unique_chars = []
    unique_ch_b = 0
    char_space = None
    filename = None
    batch = False
    check_database = False
    append_file = False

    def __init__(self):
        super().__init__('word-list', 'Generates a wordlist based on one word (generally, company name)')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('--batch',
                           action='store_true',
                           default=False,
                           dest=f'batch',
                           help=Color.s(
                               'Never ask for user input, use the default behavior'))

        flags.add_argument('--append',
                           action='store_true',
                           default=False,
                           dest=f'append_file',
                           help=Color.s(
                               'Append to the output file'))

    def add_commands(self, cmds: _ArgumentGroup):
        cmds.add_argument('--name', action='store', dest='name', help='Name')
        cmds.add_argument('-o', '--out-file', action='store', default='', dest=f'out_file',
                          help=Color.s('Write generate wordlist to a file'))
        cmds.add_argument('-min', '--min-lenght', default=1, type=int, dest='min_lenght',
                          help='Minumin word lenght')
        cmds.add_argument('-max', '--max-lenght', default=32, type=int, dest='max_lenght',
                          help='Maximum word lenght.')
        cmds.add_argument('-p', '--padding', action='store_true',  dest='padding', default=False,
                          help='Add padding to fill string to match minimun leght')
        cmds.add_argument('-nol', '--no-leets', action='store_true', dest='no_leets', default=False,
                          help='No Leets')
        cmds.add_argument('-l', '--level', default=3, type=int, dest='level',
                          help='Level of used characters. (default: 3)')

    def load_from_arguments(self, args: Namespace) -> bool:

        if args.out_file is None or args.out_file.strip() == '' or \
                args.name is None or args.name.strip() == '':
            Tools.mandatory()

        if not os.path.isdir(Path(args.out_file).parent):
            Logger.pl('{!} {R}error: Output filename is invalid {O}%s{R} {W}\r\n' % (
                args.out_file))
            Tools.exit_gracefully(1)

        self.name = args.name
        self.min_size = int(args.min_lenght)
        self.max_size = int(args.max_lenght)
        self.padding = args.padding
        self.no_leets = args.no_leets
        self.batch = args.batch
        self.append_file = args.append_file
        self.filename = args.out_file
        self.level = args.level

        try:
            with open(self.filename, 'a', encoding="UTF-8") as f:
                pass
        except IOError as x:
            if x.errno == errno.EACCES:
                Logger.pl('{!} {R}error: could not open NTLM hashes file {O}permission denied{R}{W}\r\n')
                Tools.exit_gracefully(1)
            elif x.errno == errno.EISDIR:
                Logger.pl('{!} {R}error: could not open NTLM hashes file {O}it is an directory{R}{W}\r\n')
                Tools.exit_gracefully(1)
            else:
                Logger.pl('{!} {R}error: could not open NTLM hashes file {W}\r\n')
                Tools.exit_gracefully(1)

        # Database not yet needed
        #self.db = self.open_db(args)

        return True

    def setup(self):

        if self.level < 1:
            self.level = 1

        if self.level == 1:
            self.no_leets = True

        if self.min_size < 1:
            self.min_size = 1

        if self.no_leets:
            self.char_space = LEETS2
        elif self.small or self.level == 2:
            self.char_space = LEETS3
        else:
            self.char_space = LEETS1

        # Add non listed chars (and used by name) in char_space
        self.char_space = {
            **self.char_space,
            **{
                c: c for c in self.name
                if self.char_space.get(c, None) is None
            }
        }

        self.unique_chars = set([v for l1 in [list(value) for value in self.char_space.values()] for v in l1])
        self.unique_ch_b = int(np.sum([len(v.encode("UTF-8")) for v in self.unique_chars]))

    def run(self):
        self.setup()

        estimated_size = self.calculate()
        Logger.pl(
            '{+} {W}KnowsMore will generate +- the following amount of data: {O}%s{W}.' % Tools.sizeof_fmt(
                estimated_size, start_unit="K")
        )
        stat = shutil.disk_usage(Path(self.filename).parent)
        if stat.free/1024 < estimated_size + (estimated_size * 0.2):
            Logger.pl('{!} {R}error: not enough disk space.{W}\r\n')
            Tools.exit_gracefully(1)

        # 3GB
        if estimated_size > 1073741824 and not self.batch:

            Logger.p(
                '{!} {W}Do you want continue? (Y/n): {W}')
            c = input()
            if c.lower() != 'y' and c.lower() != '':
                exit(0)
            print(' ')

        Color.pl('{?} {W}{D}Generating the wordlist wit +- {G}%s{W}{D}, please wait...{W}' % Tools.sizeof_fmt(estimated_size, start_unit="K"))
        count = 0
        lines = 0
        last = 0
        try:
            with open(self.filename, 'w' if not self.append_file else 'a', encoding="UTF-8") as f:
                with progress.Bar(label=" Generating ", expected_size=(estimated_size * 1024.0) + 1, every=1024) as bar:
                    try:
                        for w in self.generate(self.name, 0):
                            txt = f'{w}\n'
                            count += len(txt)
                            lines += 1

                            f.write(f'{w}\n')

                            if count & (1024 * 100) == 0:
                                if count > last:
                                    if count > bar.expected_size:
                                        bar.expected_size = count
                                    bar.show(count)
                                    last = count

                    except KeyboardInterrupt as e:
                        raise e
                    finally:
                        bar.hide = True
                        Tools.clear_line()

        except KeyboardInterrupt as e:
            raise e
        except IOError as x:
            if x.errno == errno.EACCES:
                Logger.pl('{!} {R}error: could not open NTLM hashes file {O}permission denied{R}{W}\r\n')
                Tools.exit_gracefully(1)
            elif x.errno == errno.EISDIR:
                Logger.pl('{!} {R}error: could not open NTLM hashes file {O}it is an directory{R}{W}\r\n')
                Tools.exit_gracefully(1)
            else:
                Logger.pl('{!} {R}error: could not open NTLM hashes file {W}\r\n')
                Tools.exit_gracefully(1)
        finally:
            file_stats = os.stat(self.filename).st_size
            Logger.pl('{+} {W}Generate {O}%d{W} lines ({O}%s{W}) to {G}%s{W}' % (lines, Tools.sizeof_fmt(file_stats), self.filename))

    def calculate(self) -> int:

        if self.name is None:
            return 0

        if not isinstance(self.name, str):
            raise Exception("Invalid type received: %s" % type(self.name))

        if self.name.strip() == 0:
            return 0

        if self.char_space is None:
            self.setup()

        s = len(self.name)
        leet_lines = np.prod([len([chars for chars in self.char_space.get(c)]) for c in self.name])
        padding_space = 0
        if len(self.name) < self.min_size and self.padding:
            s1 = self.min_size - len(self.name)
            if s1 > 0:
                pl = math.pow(len(self.unique_chars), s1)
                padding_space = (
                    ((pl * leet_lines) * (s1 + s + 1))
                    + (math.pow(self.unique_ch_b - len(self.unique_chars), s1) * (self.unique_ch_b - len(self.unique_chars)) * (s1 + 1))
                ) * 2
        common_space = np.sum([len(line) + 1 for line in self.add_common(self.name)])

        r = int(
            float(s + 1)/1024.0 +
            float(leet_lines * (s + 1))/1024.0 +
            float((float(leet_lines)/1024.0) * (float(common_space)/1024.0))*1024.0 +
            float(padding_space)/1024.0
        )
        if r < 0:
            r = 0
        return r

    def generate(self, word, index) -> list:

        if index <= 1:
            if self.name is None:
                return []

            if not isinstance(self.name, str):
                raise Exception("Invalid type received: %s" % type(self.name))

            if self.name.strip() == 0:
                return []

        c = word[index:index + 1]
        if c in self.char_space:
            for i, s in enumerate(self.char_space.get(c)):
                if index == len(word) - 1:
                    p = "%s%s" % (word[0:index], s)
                    if len(p) < self.min_size and self.padding:
                        yield from self.add_padding(p)
                    else:
                        yield p
                    yield from self.add_common(p)
                else:
                    p = "%s%s%s" % (word[0:index], s, word[index + 1:])
                    yield from self.generate(p, index + 1)

    def add_padding(self, word):
        s1 = self.min_size - len(word)
        if s1 > 0:
            for c in list(self.permutation(self.unique_chars, s1)):
                yield "%s%s" % (word, c)
                yield "%s%s" % (c, word)

    def add_common(self, word):

        year = datetime.datetime.now().year
        y2 = int(str(year)[2:4])

        for c in COMMON:
            if self.min_size <= len(word) + len(c) <= self.max_size:
                yield "%s%s" % (word, c)
                yield "%s%s" % (c, word)

        if self.min_size <= len(word) + 1 <= self.max_size:
            for s in SPECIAL:
                yield "%s%s" % (word, s)
                yield "%s%s" % (s, word)

                for c in COMMON:
                    if self.min_size <= len(word) + 1 + len(c) <= self.max_size:
                        yield "%s%s%s" % (word, s, c)
                        yield "%s%s%s" % (c, s, word)
                        if not self.small and self.level >= 2:
                            yield "%s%s%s" % (word, c, s)
                            yield "%s%s%s" % (s, c, word)

        if self.min_size <= len(word) + 3 <= self.max_size:
            for n in range(0, y2 + 15):
                yield "%s%s" % (word, n)
                yield "%s%s" % (n, word)
                for s in SPECIAL:
                    yield "%s%s%s" % (word, s, n)
                    yield "%s%s%s" % (n, s, word)
                    yield "%s%s%02d" % (word, s, n)
                    yield "%02d%s%s" % (n, s, word)

                    if not self.small and self.level >= 3:
                        yield "%s%s%s" % (word, n, s)
                        yield "%s%s%s" % (s, n, word)
                        yield "%s%02d%s" % (word, n, s)
                        yield "%s%02d%s" % (s, n, word)

        if self.min_size <= len(word) + 5 <= self.max_size:
            for n in range(year - 15, year + 15):
                yield "%s%s" % (word, n)
                yield "%s%s" % (n, word)
                for s in SPECIAL:
                    yield "%s%s%s" % (word, s, n)
                    yield "%s%s%s" % (n, s, word)
                    yield "%s%s%04d" % (word, s, n)
                    yield "%04d%s%s" % (n, s, word)

                    if not self.small and self.level >= 3:
                        yield "%s%s%s" % (word, n, s)
                        yield "%s%s%s" % (s, n, word)
                        yield "%s%04d%s" % (word, n, s)
                        yield "%s%04d%s" % (s, n, word)

    def permutation(self, char_space: list, size: int) -> list:
        if size <= 0:
            return []

        # Create a temp array that will be used by
        # allLexicographicRecur()
        data = [""] * (size + 1)

        # Sort the input string so that we get all output strings in
        # lexicographically sorted order
        source = sorted(char_space)

        # Now print all permutations
        yield from self._perm(source, data, size - 1, 0)

    def _perm(self, char_space: list, data: list, size: int, index: int):
        length = len(char_space)

        # One by one fix all characters at the given index and
        # recur for the subsequent indexes
        for i in range(length):

            # Fix the ith character at index and if this is not
            # the last index then recursively call for higher
            # indexes
            data[index] = char_space[i]

            # If this is the last index then print the string
            # stored in data[]
            if index == size:
                yield ''.join(data)
            else:
                yield from self._perm(char_space, data, size, index + 1)




