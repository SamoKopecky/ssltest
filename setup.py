import setuptools

setuptools.setup(
    name='ssltest',
    description='',
    version='0.1.1',
    author='Penterep, Samuel Kopecky',
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
                      'pyOpenSSL', 'python3-nmap', 'requests', 'urllib3'],
    entry_points={'console_scripts': ['scriptname = ssltest.Script:main']},
    include_package_data=True
)
