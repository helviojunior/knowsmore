import hashlib
import codecs

from knowsmore.util.color import Color
from knowsmore.util.tools import Tools


class Password(object):
    ntlm_hash = ''
    clear_text = ''
    latin_clear_text = ''
    length = lower = upper = digit = special = latin = 0
    md5_hash = sha1_hash = sha256_hash = sha512_hash = ''

    def __init__(self, ntlm_hash: str, clear_text: str):
        self.ntlm_hash = ntlm_hash
        self.clear_text = clear_text
        self.latin_clear_text = clear_text
        btxt = clear_text.encode("UTF-8")

        if '$HEX[' in self.clear_text:
            btxt = codecs.decode(self.clear_text[5:-1], 'hex_codec')

        self.analyze(btxt)
        self.cal_hashes(btxt)

        if '$HEX[' in self.clear_text:
            try:
                self.clear_text = btxt.decode("UTF-8")
            except UnicodeDecodeError:
                try:
                    self.latin_clear_text = btxt.decode("Latin-1")
                except:
                    pass

                Color.pl('{?} {W}{D}the password ({W}{C}%s{W}{D}) contains Latin character, '
                         'keeping HEX encoded ({W}{C}%s{W}{D}).{W}' % (self.latin_clear_text, self.clear_text))

    def analyze(self, password: bytes):
        self.length = len(password)
        for b in password:
            try:

                c = bytes([b]).decode("UTF-8")[0]

                # counting lowercase alphabets
                if c.islower():
                    self.lower += 1

                # counting uppercase alphabets
                elif c.isupper():
                    self.upper += 1

                # counting digits
                elif c.isdigit():
                    self.digit += 1

                # counting the mentioned special characters
                else:
                    self.special += 1

            except UnicodeDecodeError:
                self.latin += 1

    def cal_hashes(self, password: bytes):
        self.md5_hash = hashlib.md5(password).hexdigest().lower()
        self.sha1_hash = hashlib.sha1(password).hexdigest().lower()
        self.sha256_hash = hashlib.sha256(password).hexdigest().lower()
        self.sha512_hash = hashlib.sha512(password).hexdigest().lower()

    def __str__(self):
        return f'''NTLM........: {self.ntlm_hash}
Clear Text..: {self.clear_text}
Latin Text..: {self.latin_clear_text}
MD5.........: {self.md5_hash}
SHA1........: {self.sha1_hash}
SHA256......: {self.sha256_hash}
SHA512......: {self.sha512_hash}
Length......: {self.length}
Lower......: {self.lower}
Upper......: {self.upper}
Digit......: {self.digit}
Special......: {self.special}
Latin......: {self.latin}
'''


