from setuptools import setup, find_packages
import os

setup(
    name='PythonValidGen',
    version='1.3',
    author='Ana Almeida, André Figueiredo, Luís Ferreira',
    packages=find_packages(),
    package_data={
        # If any package contains *.txt files, include them:
        "Templates": ["*.txt"]
    },
    include_package_data=True,
    data_files=[
        (os.path.join('Python_Module_Data', 'Template'),
         [os.path.join('PythonValidGen', 'Generator', 'Templates', 'template0.txt'),
          os.path.join('PythonValidGen', 'Generator', 'Templates', 'template1.txt')]),
    ],
    license='LICENSE',
    url="https://github.com/LEImDL/PythonValidGen",
    description='Generator capable of verifying the structure of a document and generate a Python program that can process an exemplar',
    long_description_content_type='text/markdown',
    long_description=open('README.md').read(),
    install_requires=[
        "jsonschema",
        "xmltodict",
        "datetime",
        "cbor2",
        "pycose",
        "cryptography",
    ],
)
