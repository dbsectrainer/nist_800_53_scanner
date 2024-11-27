from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="nist-800-53-compliance-scanner",
    version="0.1.0",
    author="Enterprise Security Team",
    author_email="security@example.com",
    description="A comprehensive NIST 800-53 security compliance scanning platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/nist-800-53-scanner",
    packages=find_packages(exclude=['tests*']),
    install_requires=[
        'boto3',
        'azure-identity',
        'google-cloud-iam',
        'paramiko',
        'scikit-learn',
        'numpy',
        'pandas',
        'fastapi',
        'uvicorn',
        'pydantic',
        'python-jose[cryptography]',
        'passlib[bcrypt]',
        'sqlalchemy',
        'alembic',
        'redis',
        'celery',
        'prometheus-client',
        'opentelemetry-api',
        'opentelemetry-sdk',
        'jaeger-client'
    ],
    extras_require={
        'dev': [
            'pytest',
            'pytest-asyncio',
            'pytest-cov',
            'black',
            'isort',
            'mypy'
        ],
        'cloud': [
            'kubernetes',
            'docker',
            'google-cloud-functions',
            'aws-lambda-powertools'
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'nist-scanner=scan:main',
        ],
    },
    project_urls={
        'Bug Reports': 'https://github.com/your-org/nist-800-53-scanner/issues',
        'Source': 'https://github.com/your-org/nist-800-53-scanner',
    },
)
