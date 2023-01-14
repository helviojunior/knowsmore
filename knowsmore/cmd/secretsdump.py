# KnowsMore secretsdump.py module
#
# This module was adapted from secretsdump.py developed by Fortra
# https://github.com/fortra/impacket/blob/master/examples/secretsdump.py
#
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Performs various techniques to dump hashes from the
#   remote machine without executing any agent there.
#   For SAM and LSA Secrets (including cached creds)
#   we try to read as much as we can from the registry
#   and then we save the hives in the target system
#   (%SYSTEMROOT%\\Temp dir) and read the rest of the
#   data from there.
#   For NTDS.dit we either:
#       a. Get the domain users list and get its hashes
#          and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
#          call, replicating just the attributes we need.
#       b. Extract NTDS.dit via vssadmin executed  with the
#          smbexec approach.
#          It's copied on the temp dir and parsed remotely.
#
#   The script initiates the services required for its working
#   if they are not available (e.g. Remote Registry, even if it is
#   disabled). After the work is done, things are restored to the
#   original state.
#
# Author from original secretsdump.py:
#   Alberto Solino (@agsolino)
#
# References from original secretsdump.py:
#   Most of the work done by these guys. I just put all
#   the pieces together, plus some extra magic.
#
#   - https://github.com/gentilkiwi/kekeo/tree/master/dcsync
#   - https://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
#   - https://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
#   - https://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
#   - https://web.archive.org/web/20130901115208/www.quarkslab.com/en-blog+read+13
#   - https://code.google.com/p/creddump/
#   - https://lab.mediaservice.net/code/cachedump.rb
#   - https://insecurety.net/?p=768
#   - https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm
#   - https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
#   - https://www.passcape.com/index.php?section=blog&cmd=details&id=15
#


# Impacket
from __future__ import division
from __future__ import print_function
import argparse
import codecs
import logging
import os
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection

from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes, \
    KeyListSecrets
from impacket.krb5.keytab import Keytab
try:
    input = raw_input
except NameError:
    pass


import errno
import os
import re
from argparse import _ArgumentGroup, Namespace
from enum import Enum
from clint.textui import progress

from knowsmore.cmdbase import CmdBase
from knowsmore.config import Configuration
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.logger import Logger
from knowsmore.util.tools import Tools

class SecretsDump(CmdBase):
    class ImportMode(Enum):
        Undefined = 0
        NTDS = 1
        Cracked = 2
        Password = 3

    filename = ''
    db = None
    mode = ImportMode.Undefined
    password = None

    def __init__(self):
        super().__init__('secrets-dump', 'Import NTLM hashes and users/machines using impacket lib')

    def add_flags(self, flags: _ArgumentGroup):
        pass

    def add_commands(self, cmds: _ArgumentGroup):

        cmds.add_argument('-target', action='store',
                          help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                               ' (if you want to parse local files)')
        cmds.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
        cmds.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
        cmds.add_argument('-system', action='store', help='SYSTEM hive to parse')
        cmds.add_argument('-bootkey', action='store', help='bootkey for SYSTEM hive')
        cmds.add_argument('-security', action='store', help='SECURITY hive to parse')
        cmds.add_argument('-sam', action='store', help='SAM hive to parse')
        cmds.add_argument('-ntds', action='store', help='NTDS.DIT file to parse')
        cmds.add_argument('-resumefile', action='store', help='resume file name to resume NTDS.DIT session dump (only '
                                                              'available to DRSUAPI approach). This file will also be used to keep updating the session\'s '
                                                              'state')
        cmds.add_argument('-outputfile', action='store',
                          help='base output filename. Extensions will be added for sam, secrets, cached and ntds')
        cmds.add_argument('-use-vss', action='store_true', default=False,
                          help='Use the VSS method instead of default DRSUAPI')
        cmds.add_argument('-rodcNo', action='store', type=int,
                          help='Number of the RODC krbtgt account (only avaiable for Kerb-Key-List approach)')
        cmds.add_argument('-rodcKey', action='store',
                          help='AES key of the Read Only Domain Controller (only avaiable for Kerb-Key-List approach)')
        cmds.add_argument('-use-keylist', action='store_true', default=False,
                          help='Use the Kerb-Key-List method instead of default DRSUAPI')
        cmds.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec',
                          help='Remote exec '
                               'method to use at target (only when using -use-vss). Default: smbexec')

        group = cmds.add_argument_group('display options')
        group.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                           help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. '
                                'Implies also -just-dc switch')
        group.add_argument('-just-dc', action='store_true', default=False,
                           help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
        group.add_argument('-just-dc-ntlm', action='store_true', default=False,
                           help='Extract only NTDS.DIT data (NTLM hashes only)')
        group.add_argument('-pwd-last-set', action='store_true', default=False,
                           help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile data')
        group.add_argument('-user-status', action='store_true', default=False,
                           help='Display whether or not the user is disabled')
        group.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')

        group = cmds.add_argument_group('authentication')
        group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH",
                           help='NTLM hashes, format is LMHASH:NTHASH')
        group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
        group.add_argument('-k', action="store_true",
                           help='Use Kerberos authentication. Grabs credentials from ccache file '
                                '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                                ' the ones specified in the command line')
        group.add_argument('-aesKey', action="store", metavar="hex key",
                           help='AES key to use for Kerberos Authentication'
                                ' (128 or 256 bits)')
        group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

        group = cmds.add_argument_group('connection')
        group.add_argument('-dc-ip', action='store', metavar="ip address",
                           help='IP Address of the domain controller. If '
                                'ommited it use the domain part (FQDN) specified in the target parameter')
        group.add_argument('-target-ip', action='store', metavar="ip address",
                           help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                                'This is useful when target is the NetBIOS name and you cannot resolve it')

    def load_from_arguments(self, args: Namespace) -> bool:

        if args.password != '':
            if args.password.strip() == '':
                Tools.mandatory()

            self.password = Password(
                ntlm_hash='',
                clear_text=args.password
            )

            self.mode = NTLMHash.ImportMode.Password

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
        if self.mode == NTLMHash.ImportMode.Password:

            pdata = {}

            if Configuration.company != '':
                pdata['company_similarity'] = self.password.calc_ratio(Configuration.company)

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

            headers = rows[0].keys()
            data = [item.values() for item in rows]

            print(tabulate(data, headers, tablefmt='psql'))

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
                    Logger.pl('{+} {C}Loaded {O}%s{W} lines' % count)

        elif self.mode == NTLMHash.ImportMode.Cracked:
            count = 0
            ignored = 0

            if Configuration.company == '':
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

            total = Tools.count_file_lines(self.filename)
            with progress.Bar(label=" Processing ", expected_size=total) as bar:
                try:
                    with open(self.filename, 'r', encoding="UTF-8", errors="surrogateescape") as f:
                        line = f.readline()
                        while line:
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

                            pdata = {}

                            password = Password(
                                ntlm_hash=c1[0].lower(),
                                clear_text=c1[1]
                            )

                            if Configuration.company != '':
                                pdata['company_similarity'] = password.calc_ratio(Configuration.company)

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
