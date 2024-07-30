#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import base64
import datetime
import os
import string, random, sys, re
import unicodedata
from ansi2image.ansi2image import Ansi2Image
from tabulate import _table_formats, tabulate, TableFormat, Line, DataRow

from knowsmore.util.color import Color

_texts = {
    'qty': 'Quantity',
    'company_similarity': 'Company Similarity'
}

class Tools:

    def __init__(self):
        pass

    @staticmethod
    def random_generator(size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for x in range(size))

    @staticmethod
    def clear_line():
        sys.stderr.write("\033[K")
        sys.stdout.write("\033[K")  # Clear to the end of line

        try:
            size = os.get_terminal_size(fd=os.STDOUT_FILENO)
        except:
            size = 50

        print((" " * size), end='\r', flush=True)
        print((" " * size), file=sys.stderr, end='\r', flush=True)

    @staticmethod
    def permited_char_filename(s):
        if s.isalpha():
            return True
        elif bool(re.match("^[A-Za-z0-9]*$", s)):
            return True
        elif s == "-":
            return True
        elif s == "_":
            return True
        elif s == ".":
            return True
        else:
            return False

    @staticmethod
    def sanitize_filename(name):
        if name is None:
          return ''
        name = Tools.strip_accents(name.strip())
        while ('  ' in name):
            name = name.replace('  ', ' ')
        name = name.replace(' ', '-')
        while ('--' in name):
            name = name.replace('--', '-')
        return ''.join(filter(Tools.permited_char_filename, name))

    @staticmethod     
    def permited_char(s):
        if s.isalpha():
            return True
        elif bool(re.match("^[A-Za-z0-9:]*$", s)):
            return True
        elif s == ".":
            return True
        elif s == ",":
            return True
        else:
            return False

    @staticmethod
    def mandatory():
        Color.pl('{!} {R}error: missing a mandatory option, use -h help{W}\r\n')
        Tools.exit_gracefully(1)

    @staticmethod
    def exit_gracefully(code=0):
        exit(code)

    @staticmethod
    def count_file_lines(filename: str):
        def _count_generator(reader):
            b = reader(1024 * 1024)
            while b:
                yield b
                b = reader(1024 * 1024)

        with open(filename, 'rb') as fp:
            c_generator = _count_generator(fp.raw.read)
            # count each \n
            count = sum(buffer.count(b'\n') for buffer in c_generator)
            return count + 1

    @staticmethod
    def clear_string(text):
        return ''.join(filter(Tools.permited_char, Tools.strip_accents(text))).strip().lower()

    @staticmethod
    def strip_accents(text):
        try:
            text = unicode(text, 'utf-8')
        except NameError:  # unicode is a default on python 3
            pass

        text = unicodedata.normalize('NFD', text) \
            .encode('ascii', 'ignore').decode("utf-8")

        return str(text).strip()

    @staticmethod
    def get_tabulated(data: list, labels: dict = None) -> str:

        if len(data) == 0:
            return ''

        i_labels = dict(
            password="Password",
            qty="Quantity",
            score="Score",
            company_similarity="Company Similarity",
            users="Users",
            machines="Machines",
            description="Description",
            group_name="Group",
            name="Username",
            right="Right"
        )

        if labels is not None or isinstance(labels, dict):
            i_labels = {**i_labels, **labels}

        headers = [
            (next(iter([
                v
                for k, v in i_labels.items()
                if h.lower() == str(k).lower()
            ]), h) if len(h) > 2 and h[0:2] != '__' else ' ')
            for h in data[0].keys()
        ]
        data = [item.values() for item in data]

        return tabulate(data, headers, tablefmt='psql')

    @staticmethod
    def get_ansi_tabulated(data: list) -> str:

        if len(data) == 0:
            return ''

        _table_formats["ccat"] = TableFormat(
            lineabove=None,
            linebelowheader=Line("", Color.s("{GR}─{W}"), Color.s("{GR}┼{W}"), ""),
            linebetweenrows=None,
            linebelow=None,
            headerrow=DataRow("", Color.s("{GR}│{W}"), ""),
            datarow=DataRow(Color.s("{W}{O}{D}"), Color.s("{W}{GR}│{W}"), ""),
            padding=1,
            with_header_hide=None,
        )

        headers = [(Tools.format_text_header(h) if len(h) > 2 and h[0:2] != '__' else ' ') for h in data[0].keys()]
        data = [item.values() for item in data]

        tmp_data = tabulate(data, headers, tablefmt='ccat')

        return tmp_data

    @staticmethod
    def format_text_header(text) -> str:
        if text in _texts.keys():
            return _texts[text]

        return text.capitalize()

    @staticmethod
    def sizeof_fmt(num, suffix="B", start_unit=""):
        started = False
        for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
            if started or start_unit.upper() == unit:
                started = True
                if abs(num) < 1024.0:
                    return f"{num:3.1f} {unit}{suffix}"
                num /= 1024.0
        return f"{num:.1f} Y{suffix}"

    @staticmethod
    def get_dict_value(data: dict, key: str, default=None):
        if data is None:
            return default

        #if not isinstance(data, dict):
        #    return

        # Return if matches
        if key in data:
            return data.get(key, default)

        # Try to locate with the key in lowercase
        return next(
            iter([
                v for k, v in data.items()
                if k.strip().lower() == key
            ]), default)

    @staticmethod
    def json_serial(obj):
        """JSON serializer for objects not serializable by default json code"""

        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode("UTF-8")

        raise TypeError("Type %s not serializable" % type(obj))

    @staticmethod
    def escape_ansi(text):
        if text is None:
            return ''

        pattern = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
        return pattern.sub('', text)
