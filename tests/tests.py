#reference: https://medium.com/assertqualityassurance/tutorial-de-pytest-para-iniciantes-cbdd81c6d761
import codecs

import pytest, sys

from knowsmore.knowsmore import KnowsMore
from knowsmore.util.color import Color


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