
class Module(object):
    name = ''
    description = ''
    module = ''
    qualname = ''
    _class = ''

    def __init__(self, name, description, module, qualname, class_name):
        self.name = name
        self.description = description
        self.module = module
        self.qualname = qualname
        self._class = class_name
        pass

    def create_instance(self):
        return self._class()


