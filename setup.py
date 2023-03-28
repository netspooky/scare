import setuptools

setuptools.setup(
    name="scare",
    version="0.3.0",
    description="scare is a multi-arch assembly REPL and emulator for your command line.",
    author="netspooky",
    license="GPLv2",
    license_files=["LICENSE.md"],
    classifiers=["License :: OSI Approved :: GNU General Public License v2 (GPLv2)"],
    install_requires=["unicorn", "keystone-engine", "capstone"],
    py_modules=["scare"],
    entry_points={
        "console_scripts": [
            "scare = scare:main",
        ]
    },
)
