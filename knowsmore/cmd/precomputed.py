import errno
import os
import re
import sqlite3
import time
from argparse import _ArgumentGroup, Namespace
from enum import Enum
from clint.textui import progress

from knowsmore.cmdbase import CmdBase
from knowsmore.config import Configuration
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.logger import Logger
from knowsmore.util.tools import Tools


class PreComputed(CmdBase):
    filename = ''
    db = None

    def __init__(self):
        super().__init__('pre-computed', 'Import password list')

    def add_flags(self, flags: _ArgumentGroup):
        pass

    def add_commands(self, cmds: _ArgumentGroup):
        cmds.add_argument('--import-passwords',
                          action='store',
                          metavar='[password file]',
                          type=str,
                          dest=f'pwd_file',
                          help=Color.s('Text file with a password list. Each line is one password'))

    def load_from_arguments(self, args: Namespace) -> bool:
        if args.pwd_file is None or args.pwd_file.strip() == '':
            Tools.mandatory()

        if not os.path.isfile(args.pwd_file):
            Logger.pl('{!} {R}error: Filename is invalid {O}%s{R} {W}\r\n' % (
                args.ntlmfile))
            Tools.exit_gracefully(1)

        try:
            with open(args.pwd_file, 'r') as f:
                # file opened for writing. write to it here
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

        self.filename = args.pwd_file
        self.db = self.open_db(args)

        return True

    def run(self):
        count = 0
        ignored = 0

        total = Tools.count_file_lines(self.filename)
        with progress.Bar(label=" Processing ", expected_size=total) as bar:
            try:
                with open(self.filename, 'r', encoding="UTF-8", errors="surrogateescape") as f:
                    line = f.readline()
                    while line:
                        try:
                            count += 1
                            bar.show(count)

                            if line.endswith('\n'):
                                line = line[:-1]
                            if line.endswith('\r'):
                                line = line[:-1]

                            if line == '':
                                continue

                            try:
                                password = Password(
                                    ntlm_hash='',
                                    clear_text=line
                                )

                                self.db.insert_ignore_one('pre_computed',
                                                          ntlm_hash=password.ntlm_hash,
                                                          md5_hash=password.md5_hash,
                                                          sha1_hash=password.sha1_hash,
                                                          sha256_hash=password.sha256_hash,
                                                          sha512_hash=password.sha512_hash,
                                                          password=password.clear_text,
                                                          )
                            except Exception as e:
                                Tools.clear_line()
                                Logger.pl('{!} {R}error: could not parse/import line {O}%d{R} => {G}%s {W}: %s\r\n' % (count, line, str(e)))
                                raise e

                        #read next line
                        finally:
                            try:
                                line = f.readline()
                            except:
                                pass

            except KeyboardInterrupt as e:
                raise e
            finally:
                bar.hide = True
                Tools.clear_line()
                Logger.pl('{+} {C}Loaded {O}%s{W} lines' % count)

    def get_ntds_columns(self):
        self.print_verbose('Getting file column design')
        limit = 50
        count = 0
        user_index = ntlm_hash_index = -1

        with open(self.filename, 'r', encoding="UTF-8", errors="surrogateescape") as f:
            line = f.readline()
            while line:
                count += 1
                if count >= limit:
                    break

                line = line.lower()
                if line.endswith('\n'):
                    line = line[:-1]
                if line.endswith('\r'):
                    line = line[:-1]

                c1 = line.split(':')
                if len(c1) < 3:
                    continue

                for idx, x in enumerate(c1):
                    if user_index == -1:
                        if '$' in x or '\\' in x:
                            user_index = idx

                    if ntlm_hash_index == -1:
                        hash = re.sub("[^a-f0-9]", '', x.lower())
                        if len(hash) == 32 and hash != "aad3b435b51404eeaad3b435b51404ee":
                            ntlm_hash_index = idx

                if user_index != -1 and ntlm_hash_index != -1:
                    break

                if user_index == -1 or ntlm_hash_index == -1:
                    user_index = ntlm_hash_index = -1

                try:
                    line = f.readline()
                except:
                    pass

        if user_index < 0 or ntlm_hash_index < 0:
            Logger.pl('{!} {R}error: import file format not recognized {W}\r\n')
            Tools.exit_gracefully(1)

        return user_index, ntlm_hash_index
