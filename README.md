# PythonValidGen - More than a Python parser!

A fantastic Python tool to parse and automate the generation of validation functions, as well as enconde and decode to/from an arbitrary data structure.

## Features

- Parse documents
- Generate validation functions
- Encode and Decode data


## Execution example

```python
from PythonValidGen.DataRepresentation.Document import Document
from PythonValidGen.Verifier.Verifier import Verifier
from PythonValidGen.Generator.Generator import Generator
    
def test_gen(specification_path, schema_path, target_path):
    document = Document(file=specification_path, extension="JSON")
    specification = document.content

    schema = Document(file=schema_path, extension="JSON")
    verifier = Verifier(schema.content)

    # Print de um warning se houver restrições contraditórias
    verifier.verify(specification)
    generator = Generator(specification, target_path)
    generator.main()

    print("File generated")
    
test_gen('JSON_Files/mDL_specification_prototype.json', 'JSON_Files/standard_format_prototype.json', 'validator_example.py')
```
