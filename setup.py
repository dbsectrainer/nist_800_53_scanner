from setuptools import setup, find_packages

setup(
    name='nist_800_53_scanner',
    version='0.1.0',
    description='NIST 800-53 Security Compliance Scanner',
    author='Security Engineering Team',
    packages=find_packages(),
    install_requires=[
        'pyyaml>=6.0',
        'boto3>=1.26.137',
        'azure-identity>=1.12.0',
        'google-cloud-core>=2.3.2',
        'paramiko>=2.12.0',
        'pywinrm>=0.4.3'
    ],
    entry_points={
        'console_scripts': [
            'nist-scanner=scan:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Security',
    ],
    python_requires='>=3.8',
)
