import jsonschema


class Verifier:
    """
    A class used to verify documents.

    Examples
    -------
    Verifying if the `specification_path`'s file uses/follows the schema defined in `schema_path`'s file
        specification_path = '../../JSON_Files/mDL_specification_prototype.json'
        schema_path = '../../JSON_Files/standard_format_prototype.json'

        document = Document(file=specification_path, extension="JSON")
        specification = document.content

        schema = Document(file=schema_path, extension='JSON')
        verifier = Verifier(schema.content)
        verifier.verify(specification)

    Methods
    -------
    verify()
        Verifies if given specification object follows loaded schema
    """

    def __init__(self, schema: dict):
        """
        Load schema from file `schema`, must be a *.json* file.

        Parameters
        ----------
        schema: dict
            Dictionary representing the schema
        """

        self.__schema = schema

    def verify(self, specification: dict):
        """
        Verifies if `specification` object follows loaded schema.

        Parameters
        ----------
        specification: dict
            Dictionary representing the specification to be verified

        Returns
        ----------
        bool
            True, if specification is valid, False, otherwise
        """

        try:
            jsonschema.validate(instance=specification, schema=self.__schema)
        except Exception as e:
            raise e

            
if __name__ == '__main__':
    from PythonValidGen.DataRepresentation.Document import Document

    import sys
    import os

    argv = sys.argv
    argc = len(argv)

    json_paths = os.path.join(os.path.dirname(__file__), "..", "..", "JSON_Files")

    if argc < 2:
        specification_path = os.path.join(json_paths, 'mDL_specification_prototype.json')
    else:
        specification_path = argv[1]

    if argc < 3:
        schema_path = os.path.join(json_paths, 'standard_format_prototype.json')
    else:
        schema_path = argv[2]

    document = Document(file=specification_path, extension="JSON")
    _specification = document.content

    _schema = Document(file=schema_path, extension='JSON')
    verifier = Verifier(_schema.content)
