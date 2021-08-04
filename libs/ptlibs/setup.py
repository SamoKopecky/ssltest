import setuptools

setuptools.setup(
    name="ptlibs",
    description="ptlibs",
    version="0.0.1",
    author="Penterep",
    author_email="d.kummel@penterep.com",
    url="https://www.penterep.com/",
    licence="GPLv3",
    packages=setuptools.find_packages(),
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3.6",
        "Environment :: Console"
    ],
    python_requires = '>=3.6',
)
