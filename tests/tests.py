#reference: https://medium.com/assertqualityassurance/tutorial-de-pytest-para-iniciantes-cbdd81c6d761
import codecs

import pytest, sys

from knowsmore.cmd.wordlist import WordList
from knowsmore.knowsmore import KnowsMore
from knowsmore.util.color import Color
from knowsmore.util.tools import Tools


def test_create_db():
    sys.argv = ['knowsmore', '-vvv', '--create-db']
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('latin-1')(sys.stdout)

    try:
        o = KnowsMore()
        o.print_banner()

        o.main()

        assert True
        #sys.exit(0)
    except Exception as e:
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        Color.pl('\n{!} {O}Full stack trace below')
        from traceback import format_exc
        Color.p('\n{!}    ')
        err = format_exc().strip()
        err = err.replace('\n', '\n{W}{!} {W}   ')
        err = err.replace('  File', '{W}{D}File')
        err = err.replace('  Exception: ', '{R}Exception: {O}')
        Color.pl(err)

        Color.pl('\n{!} {R}Exiting{W}\n')

        assert False

# test to ensure to not broke scripts ansible
#https://github.com/helviojunior/ansible-ad
def test_wordlist():
    try:

        wlc = WordList()
        wlc.small = False
        wlc.name = "test"
        wlc.max_size = len(wlc.name) + 5
        wlc.min_size = 4
        wlc.setup()
        estimated_size = wlc.calculate()
        Color.pl('{*} {W}Estimated bytes:{O} %s{W}' % Tools.sizeof_fmt(estimated_size, start_unit='K'))
        max = 512 * 1024  # 1 GB
        if estimated_size > max:
            wlc.small = True
            estimated_size = wlc.calculate()
            Color.pl('{*} {W}Estimated bytes:{O} %s{W}' % Tools.sizeof_fmt(estimated_size, start_unit='K'))

        temp = [w for w in wlc.generate(wlc.name, 0)]

        assert True
        #sys.exit(0)
    except Exception as e:
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        Color.pl('\n{!} {O}Full stack trace below')
        from traceback import format_exc
        Color.p('\n{!}    ')
        err = format_exc().strip()
        err = err.replace('\n', '\n{W}{!} {W}   ')
        err = err.replace('  File', '{W}{D}File')
        err = err.replace('  Exception: ', '{R}Exception: {O}')
        Color.pl(err)

        Color.pl('\n{!} {R}Exiting{W}\n')

        assert False

