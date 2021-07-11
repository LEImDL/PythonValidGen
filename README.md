# PythonValidGen - More than a Python parser!

A fantastic Python tool to parse and automate the generation of validation functions, as well as enconde and decode to/from an arbitrary data structure.

## Features

- Verify if documents follows an arbitrary schema
- Generate validation programs, i.e., files capable of validating digital documents following a set of rules or specification
- Read XML, JSON, CBOR files into an unique structure
- Encode and Decode data into an external format (CBOR/COSE)
- Validate exemplares of documents, f.e., mDL

## Execution example

### Verify schema
Verify if *mDL_specification_prototype1* file follows the accepted schema for files. It's possible to use a different file extension, f.e., *XML*, but it was to follow the same type of "scheme". 

```python
from PythonValidGen.DataRepresentation.Document import Document
from PythonValidGen.Verifier.Verifier import Verifier

specification_path = 'PythonValidGen/JSON_Files/mDL_specification_prototype1.json'
schema_path = 'PythonValidGen/JSON_Files/standard_format_prototype.json'

document = Document(file=specification_path, extension="JSON")
specification = document.content

schema = Document(file=schema_path, extension='JSON')
verifier = Verifier(schema.content)

try:
    verifier.verify(specification)
    print("Valid Format")
except:
    print("Invalid Format")
```

### Read files/objects + Encode/Decode Data

To load a *JSON* file, all needed is the following code.
```python
from PythonValidGen.DataRepresentation.Document import Document

specification_path = 'PythonValidGen/JSON_Files/mDL_example_document3.json'

document = Document(file=specification_path, extension="JSON")
specification = document.content
print(specification)
```

And it's as simple for *XML* files, the same can be done for *CBOR* files, needing just to change to `extension=*CBOR*`.
```python
from PythonValidGen.DataRepresentation.Document import Document

specification_path = 'Test_Files/file.xml'

document = Document(file=specification_path, extension="XML")
specification = document.content
print(specification)
```

It's possible to load data from more sources than files, for example, a *dict* object. And then convert it into a CBOR object, to finally load it.
```python
from PythonValidGen.DataRepresentation.Document import Document
from PythonValidGen.DataRepresentation.CBOR_JSON_Converter import cbor2json

s = {"document": [{"name": "Family Name", "string": {"is_binary": False, "encoding": "utf-8", "max_length": 150, "restrictions": ["punctuation", "digits"]}, "mandatory": True}]}
document = Document(content=s)
print(document.content)

cbor_obj = document.to_cbor()
print(cbor_obj)

json_obj = cbor2json(cbor_obj)
document1 = Document(content=json_obj)

assert document1.content == document.content
print(document1.content)
```

And last, but not least, converting it to a COSE object. All three operations are supported, sign, mac and encryption.

Encrypting using a symmetric key
```python
from PythonValidGen.DataRepresentation.Document import Document

specification_path = 'PythonValidGen/JSON_Files/mDL_example_document3.json'

document = Document(file=specification_path, extension="JSON")

key = b"1234567890123456"
enc = document.enc({'ALG': 'A128GCM', 'IV': b'000102030405060708090a0b0c'}, {}, key)

dec: Document = Document.decoded_cose(enc, key)

assert dec.content == document.content
print(dec.content)
```

Calculate a MAC for the document to ensure its integrity, using the same key for both operations.
```python
from PythonValidGen.DataRepresentation.Document import Document

specification_path = 'PythonValidGen/JSON_Files/mDL_example_document3.json'

document = Document(file=specification_path, extension="JSON")

key = b"1234567890123456"
mac = document.mac({'ALG': 'HMAC_256', 'IV': b'000102030405060708090a0b0c'}, {}, key)

dec: Document = Document.decoded_cose(mac, key)

assert dec.content == document.content
print(dec.content)
```

Calculate a signature for the document to ensure its integrity and non-repudiation, using assymetric cryptography. The two keys are encoded in pem format, the public key is used to verify, private key is used to sign.

```python
from PythonValidGen.DataRepresentation.Document import Document
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

specification_path = 'PythonValidGen/JSON_Files/mDL_example_document3.json'

document = Document(file=specification_path, extension="JSON")

key = load_pem_private_key(open("Test_Files/private.pem", "rb").read(), password=b"password")
sign = document.sign({'ALG': 'RS1'}, {}, key)

key = load_pem_public_key(open("Test_Files/public.pem", "rb").read())
dec: Document = Document.decoded_cose(sign, key)

assert dec.content == document.content
print(dec.content)
```


### Generate validator + Validate document
Generate a file to validate documents according an arbitrary struture, in this case mDL will be the used as proof-of-work.
To validate a driver's license document (*mDL*), first it's needed to generate the file. For a more secure/robust way to generate this type of files, first it's verified if the specification follows the accepted schema. After, the file is generated with the following name `validator_example.py`, checking if document is valid. 

Basically, there are three ways to validate.
1. import the "future" file and execute the `validate_json_file` function with the intended document. In this case, it was validated the structure beforehand, returning True for valid documents, False otherwise;
2. Executing through `system call` using *os* library, 0 meaning success and everything else failure;
3. Executing as a script in cmd.

```python
import os
from PythonValidGen.DataRepresentation.Document import Document
from PythonValidGen.Verifier.Verifier import Verifier
from PythonValidGen.Generator.Generator import Generator
    
specification_path = "PythonValidGen/JSON_Files/mDL_specification_prototype1.json"
schema_path = "PythonValidGen/JSON_Files/schema_document3.json"
target_path = "validator_example.py"
    
document = Document(file=specification_path, extension="JSON")
specification = document.content

schema = Document(file=schema_path, extension="JSON")
verifier = Verifier(schema.content)

verifier.verify(specification)

generator = Generator(specification, target_path)
generator.main()
print("File generated")
print()

from validator_example import validate_json_file
example_doc_path = "PythonValidGen/JSON_Files/mDL_example_document3.json"
schema_doc_path = "PythonValidGen/JSON_Files/schema_document3.json"

document = Document(file=example_doc_path)
document_data = document.content

schema_document = Document(file=schema_doc_path)
schema_data = schema_document.content

v = Verifier(schema_data)
v.verify(document_data)

if validate_json_file(document_data):
    print("Documento Válido")
else:
    print("Documento Inválido")

res = os.system(f"python {target_path} {example_doc_path} {schema_doc_path}")
print(res)

if res == 0:
    print("Valid Document")
else:
    print("Invalid Document")
```

