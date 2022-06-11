import setuptools

setuptools.setup(
    name='ssltest',
    description='',
    version='0.1.1',
    author='Samuel Kopecky',
    author_email='samo.kopecky@protonmail.com',
    url='https://www.penterep.com/',
    licence='GPLv3',
    packages=setuptools.find_packages(),
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3.6',
        'Environment :: Console'
    ],
    python_requires='>=3.6',
    install_requires=['ptlibs', 'cryptography',
                      'pyOpenSSL', 'python3-nmap',
                      'requests', 'urllib3'],
    entry_points={'console_scripts': [
        'ssltest = ssltest.__main__:main']},
    data_files=[('/configs', ['configs/cipher_parameters.json', 'configs/cipher_suites.json',
                              'configs/cipher_suites_sslv2.json', 'configs/english_strings.json',
                              'configs/security_levels.json'])],
    scripts=['scripts/fix_openssl_config.py'],
)
