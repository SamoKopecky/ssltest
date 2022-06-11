import setuptools

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name='ssltest',
    description='Scan web servers cryptographic parameters and vulnerabilities',
    long_description=long_description,
    long_description_content_type='text/markdown',
    version='0.1.1',
    author='Samuel Kopecky',
    author_email='samo.kopecky@protonmail.com',
    project_urls={
        'Source': 'https://github.com/SamoKopecky/ssltest',
    },
    url='https://www.penterep.io/',
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
