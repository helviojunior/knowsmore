import hashlib
import codecs
import unicodedata

from knowsmore.util.color import Color
from knowsmore.util.tools import Tools
from math import log
from Levenshtein import ratio

LEETS = {"a": "aA@49\u00e1\u00c1\u00e0\u00c0\u00c2\u00c3\u00c4\u00c5\u00e2\u00e3\u00e4\u00e5", "b": "bB8", "c": "cC\u00e7\u00c7", "d": "dD", "e": "eE32\u00c8\u00c9\u00ca\u00cb\u00e8\u00e9\u00ea\u00eb", "f": "fF", "g": "gG96", "h": "hH#", "i": "iI!1\u00cc\u00cd\u00ce\u00cf\u00ec\u00ed\u00ee\u00ef", "j": "jJ", "k": "kK", "l": "lL!1", "m": "mM", "n": "nN\u00f1\u00d1", "o": "oO04\u00d2\u00d3\u00d4\u00d5\u00d6\u00f2\u00f3\u00f4\u00f5\u00f6", "p": "pP", "q": "qQ", "r": "rR", "s": "sS5$", "t": "tT7+", "u": "uU\u00d9\u00da\u00db\u00dc\u00f9\u00fa\u00fb\u00fc", "v": "vV", "w": "wW", "x": "xX", "y": "yY\u00dd\u00fd", "z": "zZ2", "0": "0", "1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7", "8": "8", "9": "9"}

class Password(object):
    weak_bits = 30
    ntlm_hash = ''
    bytes_password = bytes()
    clear_text = ''
    latin_clear_text = ''
    length = lower = upper = digit = special = latin = 0
    md5_hash = sha1_hash = sha256_hash = sha512_hash = ''
    entropy = 0
    similarity = 0
    leets_cache = {}

    def __init__(self, ntlm_hash: str, clear_text: str):

        if ntlm_hash == '' and clear_text is not None and clear_text != '':
            import hashlib, binascii
            hash = hashlib.new('md4', clear_text.encode('utf-16le')).digest()
            ntlm_hash = binascii.hexlify(hash)
            if isinstance(ntlm_hash, bytes):
                ntlm_hash = ntlm_hash.decode("UTF-8")
            ntlm_hash = ntlm_hash.lower()

        self.ntlm_hash = ntlm_hash
        self.clear_text = clear_text
        self.latin_clear_text = clear_text
        try:
            self.bytes_password = clear_text.encode("latin-1")
        except:
            self.bytes_password = unicodedata.normalize('NFD', clear_text) \
                .encode('latin-1', 'ignore')

        if Password.leets_cache is None:
            Password.leets_cache = {}

        if '$HEX[' in self.clear_text:
            self.bytes_password = codecs.decode(self.clear_text[5:-1], 'hex_codec')

        self.analyze()
        self.cal_hashes()

        if '$HEX[' in self.clear_text:
            try:
                self.clear_text = self.bytes_password.decode("UTF-8")
            except UnicodeDecodeError:
                try:
                    self.latin_clear_text = self.bytes_password.decode("Latin-1")
                except:
                    pass

                if self.length <= 50:
                    Color.pl('{?} {W}{D}parsed password ({W}{C}%s{W}{D}) contains Latin character, '
                             'using HEX encoded ({W}{C}%s{W}{D}).{W}' % (self.latin_clear_text, self.clear_text))

    def analyze(self):

        self.length = len(self.latin_clear_text)

        self.lower = self.upper = self.digit = self.special = self.latin = 0

        # Calculate entropy
        # it raises an error if length is less than 1
        if self.length > 1:
            unique = set(self.bytes_password)
            self.entropy = int(round(self.length * log(len(unique), 2), 0))

        for idx, c in enumerate(self.latin_clear_text):

                # check latin
                try:
                    b = c.encode("Latin-1")
                    tst = b.decode("UTF-8") # will raise error if it is a latin data
                except UnicodeEncodeError:
                    self.special += 1
                    continue
                except UnicodeDecodeError:
                    self.latin += 1
                    continue

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



    def cal_hashes(self):
        self.md5_hash = hashlib.md5(self.bytes_password).hexdigest().lower()
        self.sha1_hash = hashlib.sha1(self.bytes_password).hexdigest().lower()
        self.sha256_hash = hashlib.sha256(self.bytes_password).hexdigest().lower()
        self.sha512_hash = hashlib.sha512(self.bytes_password).hexdigest().lower()

    #https://github.com/kolypto/py-password-strength/blob/master/password_strength/stats.py
    @property
    def strength(self) -> int:
        """ Get password strength as a number normalized to range {0 .. 100}.
        Normalization is done in the following fashion:
        1. If entropy_bits <= weak_bits   -- linear in range{0 .. 33} (weak)
        2. If entropy_bits <= weak_bits*2 -- almost linear in range{33 .. 66} (medium)
        3. If entropy_bits > weak_bits*3  -- asymptotic towards 100 (strong)
        :param weak_bits: Minimum entropy bits a medium password should have.
        :type weak_bits: int
        :return: Normalized password strength:
            * <33 is WEAK
            * <66 is MEDIUM
            * >66 is STRONG
        :rtype: float
        """
        WEAK_MAX = 0.333333333

        if self.entropy <= self.weak_bits:
            return int(round((WEAK_MAX * self.entropy / self.weak_bits) * float(100), 0))

        HARD_BITS = self.weak_bits*3
        HARD_VAL = 0.950

        # Here, we want a function that:
        # 1. f(x)=0.333 at x=weak_bits
        # 2. f(x)=0.950 at x=weak_bits*3 (great estimation for a perfect password)
        # 3. f(x) is almost linear in range{weak_bits .. weak_bits*2}: doubling the bits should double the strength
        # 4. f(x) has an asymptote of 1.0 (normalization)

        # First, the function:
        #       f(x) = 1 - (1-WEAK_MAX)*2^( -k*x)

        # Now, the equation:
        #       f(HARD_BITS) = HARD_VAL
        #       1 - (1-WEAK_MAX)*2^( -k*HARD_BITS) = HARD_VAL
        #                        2^( -k*HARD_BITS) = (1 - HARD_VAL) / (1-WEAK_MAX)
        #       k = -log2((1 - HARD_VAL) / (1-WEAK_MAX)) / HARD_BITS
        k = -log((1 - HARD_VAL) / (1-WEAK_MAX), 2) / HARD_BITS
        f = lambda x: 1 - (1-WEAK_MAX)*pow(2, -k*x)

        return int(round((f(self.entropy - self.weak_bits) * float(100)), 0))  # with offset

    def get_leets(self, word, index=0) -> list:
        if index == 0:
            word = word.lower()
        c = word[index:index + 1]
        if c in LEETS:
            for i, s in enumerate(LEETS.get(c)):
                if index == len(word) - 1:
                    p = "%s%s" % (word[0:index], s)
                    yield p
                else:
                    p = "%s%s%s" % (word[0:index], s, word[index + 1:])
                    yield from self.get_leets(p, index + 1)

    def calc_ratio(self, name: str, score_cutoff: float = 0.0) -> int:
        if len(name) == 0:
            return 0

        name = name.lower()

        str_pass = self.bytes_password.decode("Latin-1")

        if score_cutoff == 0.0 and len(str_pass) > 0:
            score_cutoff = len(name) / float(len(str_pass)) - 0.05

        if score_cutoff < 0.05:
            score_cutoff = 0.05

        if score_cutoff > 0.4:
            score_cutoff = 0.4

        # Use a static cache to increase speed
        if name not in Password.leets_cache.keys():
            Password.leets_cache[name] = [l1 for l1 in self.get_leets(name)]

        self.similarity = sorted(
            [round(ratio(l1, str_pass, score_cutoff=score_cutoff) * float(100)) for l1 in Password.leets_cache[name]]
        )[-1]

        if self.similarity < int(score_cutoff * float(100)):
            self.similarity = 0

        return self.similarity

    def __str__(self):

        strength = self.strength
        s = "Weak"
        if strength >= 66:
            s = "Strong"
        elif strength >= 33:
            s = "Medium"


        return f'''NTLM........: {self.ntlm_hash}
Clear Text..: {self.clear_text}
Latin Text..: {self.latin_clear_text}
MD5.........: {self.md5_hash}
SHA1........: {self.sha1_hash}
SHA256......: {self.sha256_hash}
SHA512......: {self.sha512_hash}
Entropy.....: {self.entropy}
Strength....: {strength} -> {s}
Length......: {self.length}
Lower.......: {self.lower}
Upper.......: {self.upper}
Digit.......: {self.digit}
Special.....: {self.special}
Latin.......: {self.latin}
'''
