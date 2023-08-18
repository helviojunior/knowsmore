# Knows More

## Installation

### Simple

```bash
pip3 install --upgrade knowsmore
```

### Using Virtual Environments

Python applications will use packages and modules that don’t come as part of the standard library. Sometimes, because the application may require that a particular version of the library’s interface it may conflict with installed versions.

The solution for this problem is to create a [virtual environment](https://docs.python.org/3/tutorial/venv.html), a self-contained directory tree that contains a Python installation for a particular version of Python, plus a number of additional packages.

#### Install Python `virtualenv` package

```bash
python3 -m pip install --upgrade virtualenv
```

#### Goes to current user directory

On Unix or MacOS, run:
```bash
cd ~
```

On Powershell use this command
```bash
cd cd $env:USERPROFILE
```

#### Create a Virtual Environments

```bash
python3 -m venv knowsmore-venv
```

#### Activate Virtual Environment

Once you’ve created a virtual environment, you may activate it.

On Windows, run:
```bash
.\knowsmore-venv\Scripts\Activate.ps1
```

On Unix or MacOS, run:

```bash
source knowsmore-venv/bin/activate
```

*Note:* Activating the virtual environment will change your shell’s prompt to show what virtual environment you’re using, and modify the environment so that running python will get you that particular version and installation of Python.

#### Install the knowsmore

```bash
python -m pip install -U pip
python -m pip install knowsmore
```

*Note:* As we are inside virtual environment we must use only `python` command without `2` or `3` at end.

#### Deactivate virtual environment

To deactivate a virtual environment, type:

```bash
deactivate
```

into the terminal.

#### Create the knowsmore bash 

Create a script  on `/usr/local/bin/knowsmore`

```bash
#!/bin/bash
#

prog="~/knowsmore-venv/bin/activate"
prog="${prog/#~/$HOME}"
while [ -h "${prog}" ]; do
    newProg=`/bin/ls -ld "${prog}"`

    newProg=`expr "${newProg}" : ".* -> \(.*\)$"`
    if expr "x${newProg}" : 'x/' >/dev/null; then
        prog="${newProg}"
    else
        progdir=`dirname "${prog}"`
        prog="${progdir}/${newProg}"
    fi
done

oldwd=`pwd`
progdir=`dirname "${prog}"`
if [ -d "${prog}" ]; then
  progdir=`dirname "${prog}.txt"`
fi

cd "${progdir}"
progdir=`pwd`
prog="${progdir}"/`basename "${prog}"`
cd "${oldwd}"

# add current location to path for aapt
PATH=$PATH:`pwd`;
export PATH;
source "$prog" && python -m knowsmore "$@"
```

Make it executable

```bash
chmod +x /usr/local/bin/knowsmore
```
