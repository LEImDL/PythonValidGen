import jsonschema


class Verifier:
    """
    A class used to verify documents.

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
