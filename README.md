# PythonValidGen - More than a Python parser!

A fantastic *Python* tool to parse and automate the generation of validation functions, as well as encode and decode to/from an arbitrary data structure.

## Features

- Verify if documents follow an arbitrary schema;
- Generate validation programs, i.e., files capable of validating digital documents following a set of rules or a specification;
- Read *XML*, *JSON* and *CBOR* files into an unique structure;
- Encode and Decode data into an external format (*CBOR*/*COSE*);
- Validate exemplaries of documents, f.e., *mDL*.


## JSON files format

### Document's format
There are three types of accepted document's scheme.

An array of fields, each containing two values, "name" and "value".
````json
{
  "document": [
    {
      "name": "Family Name",
      "value": "Apelido"
    },
    {
      "name": "Given Name",
      "value": "Nome"
    }
  ]
}
````
An array of fields, each containing only one value, with key being the "name", and the "value".
````json
{
  "document": [
    {
      "Family Name": "Apelido"
    },
    {
      "Given Name": "Nome"
    }
  ]
}
````
An object of fields, each containing only one value, with key being the "name", and the "value".
````json
{
  "Family Name": "Apelido",
  "Given Name": "Nome"
}
````

### Specification's schema
In this file it is modelled the format for the documents to validate, i.e., its structure, following the schema defined in the next section.
Here it is specified every field expected, its name, if it is required, and the type of value expected and its restrictions.

For example, for an obligatory family name using *utf-8* encoding, with a max length of 150, and ensuring that punctuation characters and digits are not used, all code needed is:
````json
{
  "name":"family_name",
  "string":{
    "is_binary":false,
    "encoding": "utf-8",
    "max_length": 150,
    "restrictions": ["punctuation", "digits"]
  },
  "mandatory":true
}
````

For example, for an optional birthdate (only date), that must match to someone aged 16 or over:
````json
{
  "name":"birth_date",
  "date":{
    "is_full_date":false,
    "years_or_more": 16
  },
  "mandatory":false
}
````

For example, for an optional timestamp (with an hour, minute and seconds):
````json
{
  "name":"portrait_capture_date",
  "date":{
    "is_full_date":true
  },
  "mandatory":false
}
````

For example, for an optional boolean value:
````json
{
  "name":"age_over_18",
  "boolean":{
  },
  "mandatory":false
}
````

For example, for a mandatory binary string:
````json
{
  "name":"portrait",
  "string":{
    "is_binary":true
  },
  "mandatory":true
}
````

For example, for an age field (integer value), restricting to only positive values (the same can be done to restrict the upper bound):
````json
{
  "name":"age_in_years",
  "number":{
    "is_int":true,
    "lower_bound":0
  },
  "mandatory":false
}
````


For example, for a ten characters string (containing only A, B, C, D, E, and F), binary string, a string between 10 and 20 characters (restricting the use of digits, ponctuation and whitespaces - could be also letters), and a field that accepts an array of just enumerated values, respectively:
````json
{
  "example": [
    {
      "name":"string_example",
      "string":{
        "is_binary": false,
        "length": 10,
        "alphabet": "ABCDEF",
         "encoding": "latin-1"
      },
      "mandatory":true
    },
        {
      "name":"string_example",
      "string":{
        "is_binary": true
      },
      "mandatory":true
    },
    {
      "name":"string_example",
      "string":{
        "is_binary": false,
        "min_length": 10,
        "max_length": 20,
        "restrictions": ["punctuation", "digits", "whitespaces"]
      },
      "mandatory":true
    },
    {
      "name":"string_example",
      "string":{
        "is_binary": false,
        "is_multiple_values": true,
        "enums": ["AM", "A1", "A2", "A"]
      },
      "mandatory":true
    }
  ]
}
````

For example, for a positive integer number, a float between 0 and 10 and a two-digit integer, respectively:
````json
{
  "example": [
    {
      "name":"number_example",
      "number":{
        "is_int":true,
        "lower_bound":0
      },
      "mandatory":false
    },
    {
      "name":"number_example",
      "number":{
        "is_int":false,
        "upper_bound":10,
        "lower_bound":0
      },
      "mandatory":false
    },
    {
      "name":"number_example",
      "number":{
        "is_int":true,
        "length": 2
      },
      "mandatory":false
    }
  ]
}
````

For example, for a date that happened between 10 and 30 years ago, a past date (timestamp) and a future date, respectively:
````json
{
  "example": [
    {
      "name":"date_example",
      "date":{
              "is_full_date": false,
              "years_or_more": 10,
              "years_or_less": 30
      },
      "mandatory":false
    },
    {
      "name":"date_example",
      "date":{
              "is_full_date": true,
              "past_date": true
      },
      "mandatory":false
    },
    {
      "name":"date_example",
      "date":{
              "is_full_date": false,
              "future_date": true
      },
      "mandatory":false
    }
  ]
}
````

### Standard formats for specification
All specifications must should follow the schema in *standard_format_prototype.json*. In this file it is defined the format for every field in the desired specification, for example, it is defined that every field, must have a name, and a boolean value to determine if it is mandatory.
And, also, the types of accepted fields, in addition to the four (explained in the next section) main types, there is an object, i.e., "recursive" type, because some document might have fields inside some other outer object/value.

For example, in ***mDL***:
````json
{
  "...": "...",
  "driving_privileges": [
    {
      "vehicle_category_code": "B",
      "issue_date": "2010-03-15",
      "expiry_date": "2050-03-15",
      "codes": []
    }
  ],
  "....": "..."
}
````

#### Types defined
There are four types of values supported, *strings*, *numbers*, *dates* and  *booleans*. So, in order to specify many documents without the need to redefine the same types, *types_prototype.json* was created.\
This file also contains all the accepted restrictions for every type.


## Execution example

### Verify schema - ***Verifier***
* Verify if `mDL_specification_prototype1` file follows the accepted schema for files.\
It is possible to use a different file extension, f.e., *XML*, but it has to follow the same type of "scheme".

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

### Read files/objects + Encode/Decode Data - ***Document***+***CBOR_JSON_Converter***

* To load a *JSON* file, only the following code is required.

```python
from PythonValidGen.DataRepresentation.Document import Document

specification_path = 'PythonValidGen/JSON_Files/mDL_example_document3.json'

document = Document(file=specification_path, extension="JSON")
specification = document.content
print(specification)
```

* For *XML* files, the required code is similar.

```python
from PythonValidGen.DataRepresentation.Document import Document

specification_path = 'Test_Files/file.xml'

document = Document(file=specification_path, extension="XML")
specification = document.content
print(specification)
```

* For *CBOR* files, the required code is similar.

```python
from PythonValidGen.DataRepresentation.Document import Document

specification_path = 'Test_Files/file.cbor'

document = Document(file=specification_path, extension="CBOR")
specification = document.content
print(specification)
```


It is possible to load data from more sources than files, f.e., a *dict* object. In this example, the object is later converted into a *CBOR* object, to finally load it again.

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

Last, but not least, the object is converted into a *COSE* object.\
All three operations (*encryption*, *mac* and *sign*) are supported, as well all header values defined in `PyCose` library:

- *Encrypting* using a symmetric key.

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

- Calculate a *MAC* for the document to ensure its integrity, using the same key for both operations.

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

- Calculate a *signature* for the document to ensure its integrity and non-repudiation, using assymetric cryptography. The two keys are encoded in *pem format*, the public key is used to *verify* and the private key is used to *sign*.

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

### Generate validator + Validate document  - ***Generator***+***Validator***
* Generate a file to validate documents according to an arbitrary struture.\
In this case *mDL* will be the used as proof-of-work. To validate a driver's license document (*mDL*), the file must be generated. For a more secure/robust way to generate this type of files, firstly, it is verified if the specification follows the accepted schema. After that, the file `validator_example.py` is generated, in order to check if the document is valid. 

Essentially, there are three ways to validate:
1. import the "future" file and execute the `validate_json_file` function with the intended document. In this case, the structure was validated beforehand, returning *True* for valid documents and *False* otherwise;
2. executing through `system call` using the *os* library, **0** means success and everything else means failure;
3. executing as a *script* in *cmd*.

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

