# define Python user-defined exceptions
class FormatNotSupported(Exception):
    def __init__(self, extension, message=" format not supported"):
        """
        Exception raised when an object format is not supported.

        Parameters
        ----------
        extension: str
            String representing a extension

        message: str
            String used to indicate that format is not supported
        """

        self.message = extension + message
        super().__init__(self.message)


class ContentNotLoaded(Exception):
    def __init__(self, message="Content not loaded yet"):
        """
        Exception raised when an object content hasn't been loaded.

        Parameters
        ----------
        message: str
            String used to indicate that content hasn't be loaded
        """

        super().__init__(message)


class FileAndContentIncompatible(Exception):
    def __init__(self, message="File and content not compatible"):
        """
        Exception raised when a file and content are not compatible.

        Parameters
        ----------
        message: str
            String used to indicate that file and content are not compatible
        """

        super().__init__(message)
