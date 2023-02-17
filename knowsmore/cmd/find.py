import json
import os
import sqlite3
import time
from argparse import _ArgumentGroup, Namespace
from pathlib import Path
from binascii import hexlify
from enum import Enum

from knowsmore.util.tools import Tools

from knowsmore.cmdbase import CmdBase
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.knowsmoredb import KnowsMoreDB
from knowsmore.util.logger import Logger


class Find(CmdBase):
    class FindMode(Enum):
        All = 0, "All"
        Password = 1, "Password Only"

    db = None
    find_text = ''
    out_file = None
    cracked_only = False
    json_format = False
    find_type = FindMode.All

    def __init__(self):
        super().__init__('find', 'Find an string (user, group, domain, password) at database')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('-o', '--save-to',
                           action='store',
                           default='',
                           dest=f'out_file',
                           help=Color.s(
                               'Output file to save JSON data'))

        flags.add_argument('--cracked-only',
                           action='store_true',
                           default=False,
                           dest=f'cracked_only',
                           help=Color.s('Find cracked data only'))

        flags.add_argument('--json',
                           action='store_true',
                           default=False,
                           dest=f'json_format',
                           help=Color.s('Output in JSON format instead of text table'))

    def add_commands(self, cmds: _ArgumentGroup):
        cmds.add_argument('--text',
                          action='store',
                          metavar='[text]',
                          type=str,
                          dest=f'txt_find',
                          help=Color.s('Text to look for at all columns'))

        cmds.add_argument('--password',
                          action='store',
                          metavar='[text]',
                          type=str,
                          dest=f'txt_pwd_find',
                          help=Color.s('Text to look for in password field only'))

    def load_from_arguments(self, args: Namespace) -> bool:
        if args.txt_find is not None and args.txt_find.strip() != '':
            self.find_type = Find.FindMode.All
            self.find_text = args.txt_find
        elif args.txt_pwd_find is not None and args.txt_pwd_find.strip() != '':
            self.find_type = Find.FindMode.Password
            self.find_text = args.txt_pwd_find

        if self.find_text is None or self.find_text.strip() == '':
            Logger.pl('{!} {R}error: text is invalid {O}%s{R} {W}\r\n' % (
                self.find_text))
            exit(1)

        if args.out_file is not None and args.out_file.strip() != '':
            self.out_file = Path(args.out_file).absolute()

        if self.out_file is not None:
            if os.path.exists(self.out_file):
                Logger.pl('{!} {R}error: out file ({O}%s{R}) already exists {W}\r\n' % (
                    self.out_file))
                exit(1)

        self.db = self.open_db(args)
        self.cracked_only = args.cracked_only
        self.json_format = args.json_format

        Logger.pl('     {C}find mode:{O} %s{W}' % str(self.find_type.name))
        Logger.pl('     {C}find text:{O} %s{W}' % self.find_text)
        Logger.pl('     {C}cracked only:{O} %s{W}' % self.cracked_only)

        return True

    def run(self):

        txt = f'%{self.find_text}%'
        hex = f'%{hexlify(self.find_text.encode("latin-1")).decode("UTF-8").lower()}%'
        sql = (
            'select c.credential_id, c.name, c.type, c.object_identifier, c.dn, d.domain_id, d.name as domain_name, d.object_identifier as domain_object_identifier, '
            'd.dn as domain_dn, p.password, p.ntlm_hash, p.md5_hash, p.sha1_hash, p.sha256_hash, p.sha512_hash '
            'from credentials as c '
            'inner join passwords as p '
            'on c.password_id = p.password_id '
            'inner join domains as d '
            'on c.domain_id = d.domain_id '

        )
        pwd = Password(ntlm_hash='', clear_text=self.find_text)

        if self.find_type.value == Find.FindMode.Password.value:
            sql += (
                ' where ('
                '   p.password like ? or p.password like ? '
                '   or p.ntlm_hash like ? or p.ntlm_hash like ?'
                ')'
            )
            args = [hex, txt, txt, pwd.ntlm_hash]

        else: #all
            sql += (
                ' where ('
                '   p.password like ? or p.password like ? or p.ntlm_hash like ? or p.ntlm_hash like ? '
                '   or c.name like ? or c.object_identifier like ? or c.dn like ? '
                '   or c.groups like ?'
                ')'
            )
            args = [hex, txt, pwd.ntlm_hash, txt, txt, txt, txt, txt]

        if self.cracked_only:
            sql += ' and (p.length > 0) '

        sql += ' order by c.name'

        # Look for users, groups
        rows = self.db.select_raw(
            sql=sql,
            args=args
        )

        if len(rows) == 0:
            Logger.pl('{!} {O}Nothing found with this text{W}\r\n')
            exit(0)

        news = {}
        for r in rows:
            p = r.get('password', '')
            if '$HEX[' in p:
                p1 = Password('', p)
                r['password'] = p1.latin_clear_text

            # verify it is a new password (not yet registered)
            if r['ntlm_hash'] == pwd.ntlm_hash and r['password'] == '':
                news[pwd.ntlm_hash] = pwd.clear_text

                # adjust output table
                r['password'] = self.find_text

                # register the new password
                self.db.insert_password_manually(pwd)

        if self.out_file is None and not self.json_format:
            print(Tools.get_tabulated(rows))

        else:
            dump = json.dumps(
                    {
                        'data': rows,
                        'meta': {
                            'type': 'credentials',
                            'count': len(rows),
                            'version': 1
                        }
                    }
                )

            if self.out_file is not None:
                with open(self.out_file, "a", encoding="UTF-8") as text_file:
                    text_file.write(dump)
            else:
                print(dump)

        for k, v in news.items():
            Logger.pl('{+} {O}New password cracked! MTLM: {G}%s{O} Password: {G}%s{W}' % (k, v))

        Logger.pl('{+} {O}%s{W}{C} register found{W}' % len(rows))






