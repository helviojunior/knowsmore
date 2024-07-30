import json
import os
import sqlite3
import time
from argparse import _ArgumentGroup, Namespace
from pathlib import Path

from ansi2image.ansi2image import Ansi2Image
from binascii import hexlify
from enum import Enum

from knowsmore.util.tools import Tools

from knowsmore.cmdbase import CmdBase
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.knowsmoredb import KnowsMoreDB
from knowsmore.util.logger import Logger


class Credentials(CmdBase):
    db = None
    out_file = None
    out_path = None
    out_file_json = None

    def __init__(self):
        super().__init__('credentials', 'Show cracked credentials')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('--save-to',
                           action='store',
                           default='',
                           dest=f'out_file',
                           help=Color.s(
                               'Output file to save TXT file'))

        flags.add_argument('--save-to-json',
                           action='store',
                           default='',
                           dest=f'out_file_json',
                           help=Color.s(
                               'Output file to save JSON data'))

        flags.add_argument('--save-to-img',
                           action='store',
                           default='',
                           dest=f'out_path',
                           help=Color.s(
                               'Output path to save PNG files'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:

        if args.out_file is not None and args.out_file.strip() != '':
            self.out_file = Path(args.out_file).absolute()

        if self.out_file is not None:
            if os.path.exists(self.out_file):
                Logger.pl('{!} {R}error: out file ({O}%s{R}) already exists {W}\r\n' % (
                    self.out_file))
                exit(1)

        if args.out_file_json is not None and args.out_file_json.strip() != '':
            self.out_file_json = Path(args.out_file_json).absolute()

        if self.out_file is not None:
            if os.path.exists(self.out_file):
                Logger.pl('{!} {R}error: out file ({O}%s{R}) already exists {W}\r\n' % (
                    self.out_file))
                exit(1)

        if args.out_path is not None and args.out_path.strip() != '':
            self.out_path = Path(args.out_path).absolute()

        if self.out_path is not None:
            if not os.path.isdir(self.out_path):
                Logger.pl('{!} {R}error: output path ({O}%s{R}) does not exists {W}\r\n' % (
                    self.out_path))
                exit(1)

        self.db = self.open_db(args)

        return True

    def run(self):

        data = []

        domains = self.db.select('domains')
        for r in domains:

            # Domain
            rows = self.db.select_raw(
                sql='select row_number() OVER (ORDER BY c.name) AS __line, c.name, p.password '
                    'from credentials as c '
                    'inner join passwords as p '
                    'on c.password_id = p.password_id ' 
                    'where p.password <> "" and c.domain_id = ? '
                    'order by c.name ',
                args=[r['domain_id']]
            )

            if len(rows) > 0:
                data.append({
                    'type': 'credentials',
                    'domain': r['name'],
                    'description': 'Cracked credentials for %s' % r['name'],
                    'rows': rows
                })

        if self.out_file_json is not None:
            Color.pl('{?} {W}{D}Credentials saved at {W}{C}%s{W}{D}{W}' % self.out_file_json)

            with open(self.out_file_json, "a", encoding="UTF-8") as text_file:
                text_file.write(json.dumps(
                    {
                        'data': data,
                        'meta': {
                            'type': 'stats',
                            'count': len(data),
                            'version': 1
                        }
                    }
                ))

        elif self.out_path is not None or self.out_file is not None:

            for i, d in enumerate(data):
                name = f"{i:03}_{Tools.sanitize_filename(d['description'])}"
                file_data = ' \033[38;5;52m=\033[38;5;88m=\033[38;5;124m=\033[38;5;160m=\033[38;5;196m> ' + Color.s(
                    '{W}{G}%s{W}\n' % d['description'])

                file_data += ''.join([
                    '%s─' % c for k, c in sorted(Color.gray_scale.items(), key=lambda x: x[0], reverse=True)
                ]) + Color.s('{W}\n')

                Color.pl('{?} {W}{D}Saving %s...{W}' % d['description'])

                if len(data) == 0:
                    file_data += Color.s(
                        '\n  {R}ATTENTION!!!{O} \n  %s{W}\n' % 'Table is empty')
                else:
                    file_data += Tools.get_ansi_tabulated(d['rows'])

                if self.out_path is not None:
                    o = Ansi2Image(0, 0, font_name=Ansi2Image.get_default_font_name(), font_size=13)
                    o.loads(file_data)
                    o.min_margin = 10
                    o.max_margin = 30
                    o.calc_size(margin=0.01)
                    o.save_image(os.path.join(self.out_path, f'{name}.png'), format='PNG')

                if self.out_file is not None:
                    name = str(self.out_file).replace(Path(self.out_file).suffix, "").rstrip(". ")

                    with open(f'{name}.ansi.txt', 'ab+') as f:
                        f.write(file_data.encode('utf-8', 'ignore'))
                        f.write(b"\n\n")

                    with open(f'{name}.txt', 'ab+') as f:
                        f.write(f"{d['description']}\n".encode('utf-8', 'ignore'))
                        f.write(Tools.get_tabulated(d['rows']).encode('utf-8', 'ignore'))
                        f.write(b"\n\n")

        else:

            for d in data:
                Color.pl('{?} {W}{D}%s{W}' % d['description'])
                print(Tools.get_tabulated(d['rows']))
                print(' ')






