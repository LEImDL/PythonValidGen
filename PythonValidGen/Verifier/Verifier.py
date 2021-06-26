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
