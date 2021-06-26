# define Python user-defined exceptions
class ExceptionValidation(Exception):
    def __init__(self, message, code, *args):
        """
        Exceptions related to ValidationFunctions.

        Parameters
        ----------
        message: str
            String's format to be utilized in `format` function

        code: int
            Integer that identifies the type of the exception thrown

            Possible values:\n
            100 -> Unknown restrictions\n
            101 -> Characters not allowed\n
            102 -> Characters not defined in alphabet\n
            200 -> Invalid length\n
            201 -> Exceeds Maximum length\n
            202 -> Exceeds Minimum length\n
            300 -> Multiples values for singleton value\n
            400 -> Not Encoded in Base64\n
            401 -> String value is not String\n
            402 -> Not Encoded in given Encoding\n
            500 -> Value not defined in Enum\n
            600 -> Numerical value is not Integer\n
            601 -> Numerical value is not Numeric\n
            700 -> Invalid length (numeric representation)\n
            701 -> Exceeds Maximum value\n
            702 -> Exceeds Minimum value\n
            800 -> Boolean value is not Boolean\n
            900 -> Date value is not String\n
            901 -> Incorrect format for date\n
            902 -> Future date, but past requested\n
            903 -> Past date, but future requested\n
            904 -> Exceeds Maximum years limit\n
            905 -> Exceeds Minimum years limit

        args: *List
            The placeholders' values used for `format` function
        """
        self.message = message.format(*args)
        self.code = code
        super().__init__(self.message)
