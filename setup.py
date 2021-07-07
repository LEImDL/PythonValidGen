from setuptools import setup, find_packages
import os

setup(
    name='PythonValidGen',
    version='1.5.5',
    author='Ana Almeida, André Figueiredo, Luís Ferreira',
    packages=find_packages(),
    package_data={
        # If any package contains *.txt files, include them:
        "Templates": ["*.txt"],
        "JSON": ["*.json"]
    },
    include_package_data=True,
    data_files=[
        (os.path.join('Python_Module_Data', 'Template'),
         [os.path.join('PythonValidGen', 'Generator', 'Templates', 'template0.txt'),
          os.path.join('PythonValidGen', 'Generator', 'Templates', 'template1.txt'),
          ]),
        (os.path.join('Python_Module_Data', 'JSON_Files'),
         [os.path.join('PythonValidGen', 'JSON_Files', 'mDL_example_document.json'),
          os.path.join('PythonValidGen', 'JSON_Files', 'mDL_example_document1.json'),
          os.path.join('PythonValidGen', 'JSON_Files', 'mDL_example_document2.json'),
          os.path.join('PythonValidGen', 'JSON_Files', 'mDL_example_document3.json'),
          os.path.join('PythonValidGen', 'JSON_Files', 'mDL_specification_prototype.json'),
          os.path.join('PythonValidGen', 'JSON_Files', 'mDL_specification_prototype1.json'),
          os.path.join('PythonValidGen', 'JSON_Files', 'schema_document.json'),
          os.path.join('PythonValidGen', 'JSON_Files', 'schema_document1.json'),
          os.path.join('PythonValidGen', 'JSON_Files', 'schema_document2.json'),
          os.path.join('PythonValidGen', 'JSON_Files', 'schema_document3.json'),
          os.path.join('PythonValidGen', 'JSON_Files', 'standard_format_prototype.json'),
          os.path.join('PythonValidGen', 'JSON_Files', 'types_prototype.json'),
          ])
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
