import json
from argparse import _ArgumentGroup, Namespace
from binascii import hexlify
import random
import string
from clint.textui import progress


from knowsmore.cmdbase import CmdBase
from knowsmore.password import Password
from knowsmore.util.color import Color
from knowsmore.util.database import Database
from knowsmore.util.knowsmoredb import KnowsMoreDB
from knowsmore.util.logger import Logger
from knowsmore.util.tools import Tools


class Wipe(CmdBase):
    db = None
    pre_computed = False

    def __init__(self):
        super().__init__('wipe', 'Wipe critical data. (Clear text password and hashes)')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('--pre-computed-only',
                           action='store_true',
                           default=False,
                           dest=f'pre_computed_only',
                           help=Color.s(
                               'Wipe just pre computed passwords(default: {G}false{W}).{W}'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:
        self.db = self.open_db(args)
        self.pre_computed = args.pre_computed_only

        return True

    def run(self):
        challenge_text = ''.join(
            [random.choice(string.digits + string.ascii_lowercase) for i in range(6)])
        text = ''
        first = True

        Logger.pl('{!} {R}ALERT!{W} this process will destroy all%s {G}clear text passwords{W} and {G}hashes{W}. '
                  'But will keep user data and statistics.{W}' % (' (pre-computed)' if self.pre_computed else ''))

        while text != challenge_text:
            try:
                if not first:
                    Logger.pl('{!} {R}Wrong challenge text!{W}.')

                print('')
                Logger.p('{O}Type the text {G}%s{O} and press ENTER to confirm: {W}' % challenge_text)
                text = input()
                first = False

            except (KeyboardInterrupt, EOFError):
                print('')
                print('')
                Logger.pl('{!} {O}Wipe cancelled! {R}Nothing was destroyed!{W}')
                raise KeyboardInterrupt()

        if text == challenge_text:
            passwords = self.db.select('passwords')
            pre_cnt = self.db.select_count('pre_computed')

            count = pre_cnt
            print('')
            Color.pl('{?} {W}{D}destroying passwords data...{W}' + ' ' * 50)
            self.db.delete('pre_computed')
            if not self.pre_computed:
                with progress.Bar(label="Processing ", expected_size=len(passwords)) as bar:
                    try:
                        for idx, pwd in enumerate(passwords):
                            bar.show(idx)

                            fake_data = f"WIPE_{idx}"
                            self.db.update('passwords',
                                           filter_data={'password_id': pwd['password_id']},
                                           ntlm_hash=fake_data,
                                           md5_hash=fake_data,
                                           sha1_hash=fake_data,
                                           sha256_hash=fake_data,
                                           sha512_hash=fake_data,
                                           password=fake_data if pwd['length'] > 0 else '',
                                           )
                            count = pre_cnt + idx

                    except (KeyboardInterrupt, EOFError):
                        bar.hide = True
                        Tools.clear_line()
                        print('')
                        print('')
                        Logger.pl('{!} {O}Wipe cancelled! {G}%d{O} from {G}%d{O} data was {R}destroyed{O}!{W}' %
                                  (count, len(passwords)))
                        raise KeyboardInterrupt()
                    finally:
                        bar.hide = True
                        Tools.clear_line()

            if self.pre_computed:
                Logger.pl('{+} {O}Only Pre-computed passwords and hashes wiped! {G}%d{R} data was destroyed!{W}' % count)
            else:
                Logger.pl('{+} {O}Passwords and hashes wiped! {G}%d{R} data was destroyed!{W}' % count)







