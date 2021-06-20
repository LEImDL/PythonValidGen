# define Python user-defined exceptions
class FileAlreadyExists(Exception):
    def __init__(self, filename, message=" already exists"):
        """
        Exception raised when a file with a given filename already exists.

        Parameters
        ----------
        filename: str
            String with the name of the file

        message: str, optional
            String used to indicate that file already exists (default " already exists")
        """

        self.message = filename + message
        super().__init__(self.message)


# define Python user-defined exceptions
class FileNotFound(Exception):
    def __init__(self, filename, message=" missing"):
        """
        Exception raised when a file with a given filename hasn't been found.

        Parameters
        ----------
        filename: str
            String with the name of the file

        message: str, optional
            String used to indicate that file is missing (default " missing")
        """

        self.message = filename + message
        super().__init__(self.message)


# define Python user-defined exceptions
class DuplicatedFields(Exception):
    def __init__(self, field, message=" field(s) duplicated"):
        """
        Exception raised when *json* file has 2 fields with the same name.

        Parameters
        ----------
        field: str
            String with the duplicated field(s)

        message: str, optional
            String used to indicate that field(s) is/are duplicated (default " field(s) duplicated")
        """

        self.message = field + message
        super().__init__(self.message)
