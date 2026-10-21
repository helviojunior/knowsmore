#!/usr/bin/python3
# -*- coding: UTF-8 -*-

'''
The build version is auto update by local git hook at .git/hooks/pre-push with the following content

#!/bin/bash

build=$(printf '0x%x' $(date +%s))
meta=$(cat knowsmore/__meta__.py | sed "s/__build__.*/__build__ = "${build}"/")
echo "$meta" > knowsmore/__meta__.py

git add ./knowsmore/__meta__.py
git commit -m "Update build version"

'''

import os
import sys

try:
    from setuptools import setup, find_packages
except ImportError:
    # Python 3.12+ no longer ships setuptools in fresh environments.
    # Bootstrap it so that `python setup.py sdist` keeps working.
    import subprocess

    subprocess.check_call([sys.executable, "-m", "pip", "install", "setuptools", "wheel"])
    from setuptools import setup, find_packages

meta = {}
here = os.path.abspath(os.path.dirname(__file__))

with open(f"{here}/knowsmore/__meta__.py") as f:
    exec(f.read(), meta)

# When building a local/unreleased copy (version still 0.0.0), stamp a unique
# development version derived from the current timestamp and git commit, so that
# `pipx install --force .` produces a distinguishable build that is visible in
# the runtime banner. Released builds set a real __version__ and are left as is.
if str(meta.get("__version__", "0.0.0")).strip() == "0.0.0":
    import re

    version_file = f"{here}/VERSION"

    if os.path.isfile(version_file):
        # Reuse the version already computed for this build. A single source of
        # truth keeps every setup.py invocation of the same build (metadata step,
        # wheel step, ...) consistent; otherwise a per-call timestamp produces
        # mismatching wheel names and the build fails.
        with open(version_file, "r", encoding="utf-8") as f:
            dev_version = f.read().strip()
    else:
        import time
        import subprocess

        ts = int(time.time())
        try:
            git_hash = subprocess.check_output(
                ["git", "rev-parse", "--short=8", "HEAD"],
                cwd=here, stderr=subprocess.DEVNULL
            ).decode().strip()
        except Exception:
            git_hash = None

        # PEP 440 compliant local dev version, e.g. 0.0.0.dev1760970000+g1a2b3c4d
        dev_version = "0.0.0.dev%d" % ts + ("+g%s" % git_hash if git_hash else "")

        with open(version_file, "w", encoding="utf-8") as f:
            f.write(dev_version)

    if dev_version:
        meta["__version__"] = dev_version

        # Persist it into the packaged __meta__.py so the installed CLI banner
        # reports the same build. With pipx / PEP 517 isolated builds this edits
        # the temporary build copy; for a non-isolated build it edits the working
        # tree, so the original file is restored on exit, once the build has
        # already read and packaged the stamped version.
        meta_path = f"{here}/knowsmore/__meta__.py"
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                original_meta_src = f.read()

            patched_meta_src = re.sub(
                r"^__version__\s*=.*$",
                "__version__ = '%s'" % dev_version,
                original_meta_src,
                count=1,
                flags=re.MULTILINE,
            )
            with open(meta_path, "w", encoding="utf-8") as f:
                f.write(patched_meta_src)

            # Roll back the __meta__.py change (back to version 0.0.0) when the
            # build process exits, leaving the working tree unchanged. The VERSION
            # file is intentionally kept so the build's remaining steps reuse it;
            # delete it to force a fresh build stamp on the next install.
            import atexit

            def _restore_meta(path=meta_path, content=original_meta_src):
                try:
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(content)
                except OSError:
                    pass

            atexit.register(_restore_meta)
        except OSError:
            pass

with open(f"{here}/requirements.txt", "r", encoding="utf-8") as f:
    requires = f.read().splitlines()
    if not requires:
        print("Unable to read requirements from the requirements.txt file"
              "That indicates this copy of the source code is incomplete.")
        sys.exit(2)

with open(f"{here}/README.md", "r", encoding="utf-8") as f:
    readme = f.read()

#If you use both include_package_data and package_data, files specified with package_data will not be automatically included in sdists; you must instead list them in your MANIFEST.in

setup(
    name=meta["__title__"],
    version=meta["__version__"],
    description=meta["__description__"],
    long_description=readme,
    long_description_content_type="text/markdown",
    author=meta["__author__"],
    author_email=meta["__author_email__"],
    url=meta["__url__"],
    packages=find_packages(),
    package_data={"": ["LICENSE"]},
    data_files=[('', ['requirements.txt'])],
    #include_package_data=True,
    python_requires=">=3.8, <4",
    install_requires=requires,
    license=meta["__license__"],
    readme="README.md",
    zip_safe=False,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Operating System",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities"
    ],
    entry_points={'console_scripts': [
        'knowsmore=knowsmore.knowsmore:run',
        ]
    },
    project_urls={
        "Main Author": "https://sec4us.com.br/instrutores/helvio-junior/",
        "Documentation": "https://github.com/helviojunior/knowsmore",
        "Source": "https://github.com/helviojunior/knowsmore",
    },
)