import hashlib
import codecs

from knowsmore.util.color import Color
from knowsmore.util.tools import Tools
from math import log
from Levenshtein import ratio

LEETS = {"a":"aA@49áÁàÀ","b":"bB8","c":"cCçÇ","d":"dD","e":"eE32","f":"fF","g":"gG96","h":"hH#","i":"iI!1","j":"jJ","k":"kK","l":"lL!1","m":"mM","n":"nNñÑ","o":"oO04","p":"pP","q":"qQ","r":"rR","s":"sS5$","t":"tT7+","u":"uU","v":"vV","w":"wW","x":"xX","y":"yY","z":"zZ2","0":"0","1":"1","2":"2","3":"3","4":"4","5":"5","6":"6","7":"7","8":"8","9":"9"}

class Password(object):
    weak_bits = 30
    ntlm_hash = ''
    bytes_password = bytes()
    clear_text = ''
    latin_clear_text = ''
    length = lower = upper = digit = special = latin = 0
    md5_hash = sha1_hash = sha256_hash = sha512_hash = ''
    entropy = 0

    def __init__(self, ntlm_hash: str, clear_text: str):
        self.ntlm_hash = ntlm_hash
        self.clear_text = clear_text
        self.latin_clear_text = clear_text
        self.bytes_password = clear_text.encode("UTF-8")

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

                Color.pl('{?} {W}{D}the password ({W}{C}%s{W}{D}) contains Latin character, '
                         'keeping HEX encoded ({W}{C}%s{W}{D}).{W}' % (self.latin_clear_text, self.clear_text))

    def analyze(self):

        self.length = len(self.bytes_password)

        # Calculate entropy
        # it raises an error if length is less than 1
        if self.length > 1:
            unique = set(self.bytes_password)
            self.entropy = int(round(self.length * log(len(unique), 2), 0))

        for b in self.bytes_password:
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
            return WEAK_MAX * self.entropy / self.weak_bits

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

        return int(round(f(self.entropy - self.weak_bits) * float(100), 0))  # with offset

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

    def calc_ratio(self, name: str, score_cutoff: float = 0.4) -> int:
        str_pass = self.bytes_password.decode("Latin-1")
        return sorted(
            [round(ratio(l1, str_pass, score_cutoff=score_cutoff) * float(100)) for l1 in self.get_leets(name)]
        )[-1]

    def __str__(self):
        return f'''NTLM........: {self.ntlm_hash}
Clear Text..: {self.clear_text}
Latin Text..: {self.latin_clear_text}
MD5.........: {self.md5_hash}
SHA1........: {self.sha1_hash}
SHA256......: {self.sha256_hash}
SHA512......: {self.sha512_hash}
Entropy......: {self.entropy}
Strength......: {self.strength}
Length......: {self.length}
Lower......: {self.lower}
Upper......: {self.upper}
Digit......: {self.digit}
Special......: {self.special}
Latin......: {self.latin}
'''
