#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import sys
import colorama
from colorama import Fore, Back, Style
colorama.init(strip=False)


class Color(object):
    ''' Helper object for easily printing colored text to the terminal. '''

    _stdout = None
    _stderr = None

    # Basic console colors
    colors = {
        'W' : '\033[0m',  # white (normal)
        'R' : '\033[31m', # red
        'G' : '\033[32m', # green
        'O' : '\033[33m', # orange
        'B' : '\033[34m', # blue
        'P' : '\033[35m', # purple
        'C' : '\033[36m', # cyan
        'GR': '\033[38;5;240m', # gray
        'GR2': '\033[38;5;235m',  # gray
        'D' : '\033[2m'   # dims current color. {W} resets.
    }

    # Helper string replacements
    replacements = {
        '{+}': '{W}{D}[{W}{G}+{W}{D}]{W}',
        '{!}': '{O}[{R}!{O}]{W}',
        '{?}': '{W}{D}[{W}{C}?{W}{D}]{W}',
        '{*}': '{W}[{B}*{W}]'
    }

    gray_scale = {
        i: f'\033[38;5;{i}m' for i in range(232, 256)
    }

    last_sameline_length = 0

    @staticmethod
    def get_system_defaults():
        if Color._stdout is None:
            Color._stdout = sys.stdout

        if Color._stderr is None:
            Color._stderr = sys.stderr

    @staticmethod
    def p(text):
        '''
        Prints text using colored format on same line.
        Example:
            Color.p("{R}This text is red. {W} This text is white")
        '''
        Color._stdout.write(Color.s(text))
        Color._stdout.flush()
        if '\r' in text:
            text = text[text.rfind('\r')+1:]
            Color.last_sameline_length = len(text)
        else:
            Color.last_sameline_length += len(text)

    @staticmethod
    def pl(text):
        '''Prints text using colored format with trailing new line.'''
        Color.p('%s\n' % text)
        Color.last_sameline_length = 0

    @staticmethod
    def pe(text):
        '''Prints text using colored format with leading and trailing new line to STDERR.'''
        Color._stderr.write(Color.s('%s\n' % text))
        Color.last_sameline_length = 0

    @staticmethod
    def s(text):
        ''' Returns colored string '''
        output = text
        for (key,value) in Color.replacements.items():
            output = output.replace(key, value)
        for (key,value) in Color.colors.items():
            output = output.replace("{%s}" % key, value)
        return output

    @staticmethod
    def sc(text):
        ''' Returns non colored string '''
        output = text
        for (key,value) in Color.replacements.items():
            output = output.replace(key, value)
        for (key,value) in Color.colors.items():
            output = output.replace("{%s}" % key, '')
        return output

    @staticmethod
    def clear_line():
        spaces = ' ' * Color.last_sameline_length
        sys.stdout.write('\r%s\r' % spaces)
        sys.stdout.flush()
        Color.last_sameline_length = 0

    @staticmethod
    def clear_entire_line():
        import os
        try:
            (_, columns) = os.popen('stty size', 'r').read().split()
        except:
            columns = 150
        Color.p("\r" + (" " * int(columns)) + "\r")

    @staticmethod
    def pattack(attack_type, target, attack_name, progress):
        '''
        Prints a one-liner for an attack.
        Includes attack type (WEP/WPA), target ESSID & power, attack type, and progress.
        ESSID (Pwr) Attack_Type: Progress
        e.g.: Router2G (23db) WEP replay attack: 102 IVs
        '''
        essid = "{C}%s{W}" % target.essid if target.essid_known else "{O}unknown{W}"
        Color.p("\r{+} {G}%s{W} ({C}%sdb{W}) {G}%s {C}%s{W}: %s " % (
            essid, target.power, attack_type, attack_name, progress))


Color.get_system_defaults()
