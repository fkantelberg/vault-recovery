import os

from setuptools import find_packages, setup


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as f:
        return f.read()


setup(
    name="vault-recovery",
    version="0.2",
    author="Florian Kantelberg",
    author_email="florian.kantelberg@mailbox.org",
    description="Tool for a disaster recovery of Odoo's vault module",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    license="MIT",
    keywords="vault disaster recovery",
    url="https://github.com/fkantelberg/vault-recovery",
    packages=find_packages("src"),
    package_dir={"": "src"},
    install_requires=[
        "cryptography",
        "psycopg2",
    ],
    include_package_data=True,
    entry_points={"console_scripts": ["vault = vault.__main__:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)
