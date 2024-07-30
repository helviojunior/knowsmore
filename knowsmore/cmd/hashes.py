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


class NTLMHash(CmdBase):
    class ImportMode(Enum):
        Undefined = 0
        NTDS = 1
        Cracked = 2
        Password = 3
        ExportHashes = 4
        ExportCrackedHashes = 5

    filename = ''
    db = None
    mode = ImportMode.Undefined
    password = None

    def __init__(self):
        super().__init__('ntlm-hash', 'Import NTLM hashes and users')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('-format',
                           action='store',
                           default='secretsdump',
                           dest=f'file_format',
                           help=Color.s(
                               'Specify NTLM hashes format (default: {G}secretsdump{W}). Available methods: {G}secretsdump{W}'))

    def add_commands(self, cmds: _ArgumentGroup):
        cmds.add_argument('--export-hashes',
                          action='store',
                          metavar='[hashes file]',
                          type=str,
                          dest=f'export_file',
                          help=Color.s('NTLM hashes filename.'))

        cmds.add_argument('--import-ntds',
                          action='store',
                          metavar='[hashes file]',
                          type=str,
                          dest=f'ntlmfile',
                          help=Color.s('NTLM hashes filename.'))

        cmds.add_argument('--import-cracked',
                          action='store',
                          metavar='[cracked file]',
                          type=str,
                          dest=f'crackedfile',
                          help=Color.s('Hashcat cracked hashes filename. (format: {G}hash{R}:{G}password{W})'))

        cmds.add_argument('--export-cracked',
                          action='store',
                          metavar='[cracked file]',
                          type=str,
                          dest=f'export_cracked_file',
                          help=Color.s('Hashcat cracked hashes filename. (format: {G}hash{R}:{G}password{W})'))

        cmds.add_argument('--add-password',
                          action='store',
                          metavar='[clear text password]',
                          type=str,
                          default='',
                          dest=f'password',
                          help=Color.s('Add clear text password to database'))

    def load_from_arguments(self, args: Namespace) -> bool:

        if args.password != '':
            if args.password.strip() == '':
                Tools.mandatory()

            self.password = Password(
                ntlm_hash='',
                clear_text=args.password
            )

            self.mode = NTLMHash.ImportMode.Password

        elif args.export_file is not None and args.export_file != '':
            try:
                with open(args.export_file, 'a') as f:
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

            self.mode = NTLMHash.ImportMode.ExportHashes
            self.filename = args.export_file

        elif args.export_cracked_file is not None and args.export_cracked_file != '':
            try:
                with open(args.export_cracked_file, 'a') as f:
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

            self.mode = NTLMHash.ImportMode.ExportCrackedHashes
            self.filename = args.export_cracked_file

        else:
            if (args.ntlmfile is None or args.ntlmfile.strip() == '') and \
                    (args.crackedfile is None or args.crackedfile.strip() == ''):
                Tools.mandatory()

            if args.ntlmfile is not None and args.ntlmfile.strip() != '':
                if not os.path.isfile(args.ntlmfile):
                    Logger.pl('{!} {R}error: NTLM filename is invalid {O}%s{R} {W}\r\n' % (
                        args.ntlmfile))
                    Tools.exit_gracefully(1)

                try:
                    with open(args.ntlmfile, 'r') as f:
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

                self.mode = NTLMHash.ImportMode.NTDS
                self.filename = args.ntlmfile

            elif args.crackedfile is not None or args.crackedfile.strip() != '':
                if not os.path.isfile(args.crackedfile):
                    Logger.pl('{!} {R}error: NTLM filename is invalid {O}%s{R} {W}\r\n' % (
                        args.ntlmfile))
                    Tools.exit_gracefully(1)

                try:
                    with open(args.crackedfile, 'r') as f:
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

                self.mode = NTLMHash.ImportMode.Cracked
                self.filename = args.crackedfile

            if self.mode == NTLMHash.ImportMode.Undefined:
                Logger.pl('{!} {R}error: Nor {O}--import-ntds{R} or {O}--import-cracked{R} was provided{W}\r\n')
                Tools.exit_gracefully(1)

        self.db = self.open_db(args)

        return True

    def run(self):
        if self.mode in [NTLMHash.ImportMode.ExportHashes, NTLMHash.ImportMode.ExportCrackedHashes]:
            sql = 'select distinct p.ntlm_hash, p.password from passwords p'
            if self.mode == NTLMHash.ImportMode.ExportCrackedHashes:
                sql += ' where p.password <> ""'
            rows = self.db.select_raw(
                sql=sql,
                args=[]
            )

            Color.pl('{?} {W}{D}Exporting {O}%d{W} hashes...{W}' % len(rows))

            try:
                with open(self.filename, 'w', encoding="UTF-8") as f:
                    for row in rows:
                        if self.mode == NTLMHash.ImportMode.ExportCrackedHashes:
                            f.write(f'{row["ntlm_hash"]}:{row["password"]}\n')
                        else:
                            f.write(f'{row["ntlm_hash"]}\n')
                    pass
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
                Logger.pl('{+} {O}%d{W}{C} exported to {G}%s{W}' % (len(rows), self.filename))

        elif self.mode == NTLMHash.ImportMode.Password:

            pdata = {}

            if len(Configuration.company) > 0:
                pdata['company_similarity'] = sorted(
                            [self.password.calc_ratio(n1) for n1 in Configuration.company]
                        )[-1]

            self.db.insert_password_manually(self.password, **pdata)
            Logger.pl('{+} {C}Password inserted/updated{W}')

            print(' ')
            Color.pl('{?} {W}{D}Password data:{W}')
            print(self.password)

            Color.pl('{?} {W}{D}Looking for user with this password...{W}')

            sql = (
                'select c.credential_id, c.name, c.type, c.object_identifier, c.dn, d.domain_id, d.name as domain_name, d.object_identifier as domain_object_identifier, '
                'd.dn as domain_dn, p.password, p.ntlm_hash, p.md5_hash, p.sha1_hash, p.sha256_hash, p.sha512_hash '
                'from credentials as c '
                'inner join passwords as p '
                'on c.password_id = p.password_id '
                'inner join domains as d '
                'on c.domain_id = d.domain_id '
                ' where p.ntlm_hash like ? '
                ' order by c.name'
            )
            args = [self.password.ntlm_hash]

            rows = self.db.select_raw(
                sql=sql,
                args=args
            )

            if len(rows) == 0:
                Logger.pl('{!} {O}Password/hash inserted but none user found with this password{W}\r\n')
                exit(0)

            print(Tools.get_tabulated(rows))

            Logger.pl('{+} {O}%s{W}{C} register found{W}' % len(rows))

        elif self.mode == NTLMHash.ImportMode.NTDS:
            (user_index, ntlm_hash_index) = self.get_ntds_columns()
            min_col = -1
            if user_index > min_col:
                min_col = user_index + 1
            if ntlm_hash_index > min_col:
                min_col = ntlm_hash_index + 1

            count = 0
            ignored = 0
            pc_count = 0

            total = Tools.count_file_lines(self.filename)

            with progress.Bar(label=" Processing ", expected_size=total) as bar:
                try:
                    with open(self.filename, 'r', encoding="UTF-8", errors="surrogateescape") as f:
                        line = f.readline()
                        while line:
                            count += 1
                            bar.show(count)

                            line = line.lower()
                            if line.endswith('\n'):
                                line = line[:-1]
                            if line.endswith('\r'):
                                line = line[:-1]

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

                            # try to locate this host previously imported by BloodHound
                            domain_id = -1
                            if domain == 'default':
                                d = self.db.select_raw(
                                    sql="select c.domain_id from credentials as c "
                                        "where name = ? and domain_id <> 1 and type = ?",
                                    args=[usr, type]
                                )
                                if len(d) == 1:  # Not permit duplicity
                                    domain_id = d[0]['domain_id']

                            if domain_id == -1:
                                domain_id = self.db.insert_or_get_domain(domain)

                            if domain_id == -1:
                                Tools.clear_line()
                                Logger.pl('{!} {R}error: Was not possible to import the domain {O}%s{R}\r\n' % domain)
                                Tools.exit_gracefully(1)

                            self.db.insert_or_update_credential(
                                domain=domain_id,
                                username=usr,
                                ntlm_hash=hash,
                                type=type,
                                exclude_on_update=["object_identifier", "dn", "groups",
                                                   "enabled", "full_name"]
                            )

                            # check if exists at pre computed hashes
                            pre_computed = self.db.select('pre_computed',
                                                          ntlm_hash=hash
                                                          )
                            if len(pre_computed) > 0:

                                pc_count += 1

                                pdata = {}

                                password = Password(
                                    ntlm_hash=hash,
                                    clear_text=pre_computed[0]['password']
                                )

                                if len(Configuration.company) > 0:
                                    pdata['company_similarity'] = sorted(
                                        [password.calc_ratio(n1, 0.40) for n1 in Configuration.company]
                                    )[-1]

                                self.db.update_password(
                                    password,
                                    **pdata
                                )

                            try:
                                line = f.readline()
                            except:
                                pass

                except KeyboardInterrupt as e:
                    raise e
                finally:
                    bar.hide = True
                    Tools.clear_line()
                    if pc_count > 0:
                        Logger.pl('{+} {W}{D}Found %d hashes at pre computed table{W}' % pc_count)
                    Logger.pl('{+} {C}Loaded {O}%s{W} lines' % count)

        elif self.mode == NTLMHash.ImportMode.Cracked:
            count = 0
            ignored = 0

            if len(Configuration.company) == 0:
                Logger.pl(
                    '{!} {W}It is recommended import cracked passwords using the parameter {O}--company{W} because '
                    'the KnowsMore will calculate the score of similarity of the passwords and Company Name.'
                    )
                Logger.p(
                    '{!} {W}Do you want continue without inform company name? (y/N): {W}')
                c = input()
                if c.lower() != 'y':
                    exit(0)
                print(' ')

            Logger.pl('{+} {W}Calculating company\'s name leets{W}')
            if len(Configuration.company) > 0:
                for n in Configuration.company:
                    Password.leets_cache[n] = [l1 for l1 in Password.get_leets(n)]

            Logger.pl('{+} {W}Importing...{W}')
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

                                c1 = line.split(':', maxsplit=1)
                                if len(c1) != 2:
                                    ignored += 1
                                    continue

                                if c1[0] == '':
                                    continue

                                try:
                                    password = Password(
                                        ntlm_hash=None,  # c1[0].lower(), # not use this
                                        clear_text=c1[1]
                                    )

                                    #verify if exists
                                    pwd = self.db.select('passwords',
                                                         ntlm_hash=password.ntlm_hash
                                                         )

                                    if len(pwd) == 0:
                                        # insert just at pre_computed
                                        self.db.insert_ignore_one('pre_computed',
                                                                  ntlm_hash=password.ntlm_hash,
                                                                  md5_hash=password.md5_hash,
                                                                  sha1_hash=password.sha1_hash,
                                                                  sha256_hash=password.sha256_hash,
                                                                  sha512_hash=password.sha512_hash,
                                                                  password=password.clear_text
                                                                  )
                                        continue

                                    pdata = {}

                                    if len(Configuration.company) > 0:
                                        pdata['company_similarity'] = sorted(
                                            [password.calc_ratio(n1, 0.4) for n1 in Configuration.company]
                                        )[-1]

                                    self.db.update_password(
                                        password,
                                        **pdata
                                    )
                                except Exception as e:
                                    print(e)

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
        limit = 100
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
