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
    db = None
    find_text = ''
    out_file = None
    cracked_only = False
    json_format = False

    def __init__(self):
        super().__init__('member-of', 'Find all member of group at database')

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
        cmds.add_argument('--name',
                          action='store',
                          metavar='[text]',
                          type=str,
                          dest=f'txt_find',
                          help=Color.s('Text to look for at all columns'))

    def load_from_arguments(self, args: Namespace) -> bool:
        if args.txt_find is not None and args.txt_find.strip() != '':
            self.find_text = args.txt_find

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

        Logger.pl('     {C}find text:{O} %s{W}' % self.find_text)
        Logger.pl('     {C}cracked only:{O} %s{W}' % self.cracked_only)

        return True

    def run(self):

        sql = (
            'select row_number() OVER (ORDER BY g2.name, c.name) AS __line, g2.name group_name, '
            'c.name, p.password, be.edge_type as "right", '
            'case when c.enabled == 1 then "Yes" ELSE "No" end user_enabled '
            'from credentials as c '
            'inner join passwords as p  '
            'on c.password_id = p.password_id  '
            'inner join bloodhound_edge be  '
            'on be.source_id == c.object_identifier  '
            'and be.target_label == "Group" '
            'and be.edge_type in ("MemberOf", "Owns") '
            'inner join groups g2  '
            'on be.destination_id == g2.object_identifier  '
            'where g2.name like ? '
        )

        args = [f'%{self.find_text}%']

        if self.cracked_only:
            sql += ' and (p.password <> "") '

        sql += ' order by g2.name, c.enabled DESC, c.name'

        # Look for users
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

        p_data = Tools.get_tabulated(rows, dict(
                group_name="Group",
                name="Username",
                password="Password",
                right="Right",
                user_enabled="User Enabled?"
            ))

        if self.json_format:
            p_data = json.dumps(
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
                text_file.write(p_data)
        else:
            print(p_data)

        if not self.cracked_only:
            Logger.pl('{!} {O}You can filter cracked only users using {C}--cracked-only{O} paramater{W}\r\n')

        Logger.pl('{+} {O}%s{W}{C} register found{W}' % len(rows))

