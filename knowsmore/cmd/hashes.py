import errno
import os
import re
import sqlite3
import time
from argparse import _ArgumentGroup, Namespace

from knowsmore.cmdbase import CmdBase
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.logger import Logger
from knowsmore.util.tools import Tools


class NTLMHash(CmdBase):
    filename = ''
    db = None

    def __init__(self):
        super().__init__('ntlm-hash', 'Import NTLM hashes ans users')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('-format',
                           action='store',
                           default='secretsdump',
                           dest=f'file_format',
                           help=Color.s('Specify NTLM hashes format (default: {G}secretsdump{W}). Available methods: {G}secretsdump{W}'))

    def add_commands(self, cmds: _ArgumentGroup):
        cmds.add_argument('--import',
                          action='store',
                          metavar='[hashes file]',
                          type=str,
                          dest=f'ntlmfile',
                          help=Color.s('NTLM hashes filename.'))

    def load_from_arguments(self, args: Namespace) -> bool:
        if args.ntlmfile is None or args.ntlmfile.strip() == '':
            Logger.pl('{!} {R}error: NTLM filename is invalid {O}%s{R} {W}\r\n' % (
                args.ntlmfile))
            exit(1)

        try:
            with open(args.ntlmfile, 'r') as f:
                # file opened for writing. write to it here
                pass
        except IOError as x:
            if x.errno == errno.EACCES:
                Logger.pl('{!} {R}error: could not open NTLM hashes file {O}permission denied{R}{W}\r\n')
                exit(1)
            elif x.errno == errno.EISDIR:
                Logger.pl('{!} {R}error: could not open NTLM hashes file {O}it is an directory{R}{W}\r\n')
                exit(1)
            else:
                Logger.pl('{!} {R}error: could not open NTLM hashes file {W}\r\n')
                exit(1)

        self.filename = args.ntlmfile
        self.db = self.open_db(args)

        return True

    def run(self):
        (user_index, ntlm_hash_index) = self.get_columns()
        min_col = -1
        if user_index > min_col:
            min_col = user_index + 1
        if ntlm_hash_index > min_col:
            min_col = ntlm_hash_index + 1

        count = 0
        ignored = 0
        users = 0
        with open(self.filename, 'r', encoding="ascii", errors="surrogateescape") as f:
            line = f.readline()
            while line:
                count += 1
                line = line.lower()
                if line.endswith('\n'):
                    line = line[:-1]
                if line.endswith('\r'):
                    line = line[:-1]

                #line = ''.join(filter(Tools.permited_char, line)).strip()

                Tools.clear_line()
                print(("Processing [line %d, users %d]" % (count, users)), end='\r', flush=True)

                c1 = line.split(':')
                if len(c1) < min_col:
                    ignored += 1
                    continue

                f1 = c1[user_index]
                hash = c1[ntlm_hash_index]

                if '\\' in f1:
                    f1s = f1.strip().split('\\')
                    domain = f1s[0].strip()
                    usr = f1s[1].strip()
                else:
                    domain = 'default'
                    usr = f1.strip()

                type = 'U'

                if usr.endswith('$'):
                    usr = usr[:-1]
                    type = 'M'

                if domain == '' or usr == '' or hash == '':
                    self.print_verbose(f'Line ignored: {line}')

                didx = self.db.insert_or_get_domain(domain)
                if didx == -1:
                    Tools.clear_line()
                    Logger.pl('{!} {R}error: Was not possible to import the domain {O}%s{R}\r\n' % domain)
                    exit(1)

                users += 1
                self.db.insert_credential(
                    domain=didx,
                    username=usr,
                    ntlm_hash=hash,
                    type=type)

                try:
                    line = f.readline()
                except:
                    pass

        Tools.clear_line()
        print((" " * 180), end='\r', flush=True)
        Logger.pl('{+} {C}Loaded {O}%s{W} users' % users)

    def get_columns(self):
        self.print_verbose('Getting file column design')
        limit = 50
        count = 0
        user_index = ntlm_hash_index = -1

        with open(self.filename, 'r', encoding="ascii", errors="surrogateescape") as f:
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
            exit(1)

        return user_index, ntlm_hash_index

