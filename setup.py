import setuptools

setuptools.setup(
    name="SSLTester",
    description="",
    version="0.0.1",
    author="Penterep",
    author_email="",
    url="https://www.penterep.com/",
    licence="GPLv3",
    packages=setuptools.find_packages(),
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3.6",
        "Environment :: Console"
    ],
    python_requires='>=3.6',
    install_requires=["ptlibs", ""],
    entry_points={'console_scripts': ['scriptname = SSLTester.SSLTester:main']},
    include_package_data=True
)
