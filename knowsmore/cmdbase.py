import os
import datetime
import importlib
import pkgutil
import sys
import traceback
from argparse import _ArgumentGroup, ArgumentParser, Namespace
from pathlib import Path

from knowsmore.module import Module
from knowsmore.util.color import Color
from knowsmore.util.logger import Logger


class CmdBase(object):
    help_show = True
    name = ''
    description = ''

    def __init__(self, name, description, help_show=True):
        self.name = name
        self.description = description
        self.help_show = help_show
        pass

    @classmethod
    def get_base_module(cls) -> str:
        file = Path(__file__).stem

        parent_module = f'.{cls.__module__}.'.replace(f'.{file}.', '').strip(' .')

        return '.'.join((parent_module, 'cmd'))

    @classmethod
    def list_modules(cls, help_show=True, verbose=False) -> dict:
        try:

            base_module = CmdBase.get_base_module()

            modules = {}

            base_path = os.path.join(
                Path(__file__).resolve().parent, 'cmd'
            )

            for loader, modname, ispkg in pkgutil.walk_packages([base_path]):
                if not ispkg:
                    if verbose:
                        Color.pl('{?} Importing module: %s' % f'{base_module}.{modname}')
                    importlib.import_module(f'{base_module}.{modname}')

            if verbose:
                print('')

            for iclass in CmdBase.__subclasses__():
                t = iclass()
                if t.name in modules:
                    raise Exception(f'Duplicated Module name: {iclass.__module__}.{iclass.__qualname__}')

                if t.help_show is True or help_show is True:
                    modules[t.name] = Module(
                        name=t.name.lower(),
                        description=t.description,
                        module=str(iclass.__module__),
                        qualname=str(iclass.__qualname__),
                        class_name=iclass
                    )

            return modules

        except Exception as e:
            raise Exception('Error listing command modules', e)

    def add_flags(self, flags: _ArgumentGroup):
        pass

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:
        raise Exception('Method "load_from_arguments" is not yet implemented.')

    def run(self):
        raise Exception('Method "run" is not yet implemented.')