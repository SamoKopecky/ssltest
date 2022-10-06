from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ssltest",
    description="Scan web servers cryptographic parameters and vulnerabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    version="0.2.1",
    author="Samuel Kopecky",
    author_email="samo.kopecky@protonmail.com",
    project_urls={
        "Source": "https://github.com/SamoKopecky/ssltest",
        "Documentation": "https://ssltest.readthedocs.io/en/latest",
    },
    url="https://www.penterep.io/",
    licence="GPLv3",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3.6",
        "Environment :: Console",
    ],
    python_requires=">=3.6",
    install_requires=[
        "ptlibs",
        "cryptography",
        "pyOpenSSL",
        "python3-nmap",
        "requests",
        "urllib3",
    ],
    entry_points={"console_scripts": ["ssltest = ssltest.__main__:main"]},
    scripts=["scripts/fix_openssl_config.py"],
)
