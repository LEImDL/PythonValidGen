import re
from datetime import datetime
from typing import Union, List, Set
import string as st
from PythonValidGen.Validator.Exceptions import ExceptionValidation


def is_base64(string: str) -> bool:
    """
    Verifies if `string` is encoded in Base 64.

    Parameters
    ----------
    string: str
        String object to be verified

    Returns
    ----------
    bool
        True, if `string` complies with Base 64 format, False, otherwise
    """

    return re.match("^([A-Za-z0-9+/]{4})+([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$", string) is not None


__restrictions_dict = {'digits': st.digits, 'letters': st.ascii_letters, 'punctuation': st.punctuation,
                       'whitespace': st.whitespace}


def check_for_restrictions(string: str, restrictions: Set[str]):
    """
    Verifies if `string` complies with `restrictions`, ie. `string` can't contain characters from the `restriction`.

    Parameters
    ----------
    string: str
        String object to be verified

    restrictions: Set
        Set object containing restrictions wanted

    Raises
    ----------
    ExceptionValidation(100), if restrictions argument contains values not supported\n
    ExceptionValidation(101), if string argument contains characters defined by the imposed restrictions
    """

    # Verificar se existe uma restrição que não é 'digits', 'letters', 'punctuation', 'whitespace'
    if not restrictions.issubset(['digits', 'letters', 'punctuation', 'whitespace']):
        raise ExceptionValidation("Restrictions defined doesn't match with possible values", 100)

    pattern = set()
    for restriction in restrictions:
        pattern.update(__restrictions_dict[restriction])

    if len(set(string).intersection(pattern)) != 0:
        raise ExceptionValidation("{0} characters in {1} aren't allowed by {2}", 101,
                                  list(set(string).intersection(pattern)), string,
                                  list(restrictions))


def check_length(string: str, length: int = None, min_length: int = None, max_length: int = None):
    """
    Verifies if `string` complies with `restrictions`, ie. `string`  must be of a length that complies with the defined restrictions.

    Parameters
    ----------
    string: str
        String object to be verified

    length: int, optional
        Length wanted for `string`, if *None* then constraint isn't applied (default is None)

    min_length: int, optional
        Minimum length for `string`, if *None* then constraint isn't applied (default is None)

    max_length: int, optional
        Maximum length for `string`, if *None* then constraint isn't applied (default is None)

    Raises
    ----------
    ExceptionValidation(200), if length of string argument does not match length argument\n
    ExceptionValidation(201), if length of string argument is superior than max_length argument\n
    ExceptionValidation(202), if length of string argument is inferior than min_length argument
    """

    if length is not None and len(string) != length:
        raise ExceptionValidation("{0} doesn't have defined length: {1}", 200, string, length)
    if max_length is not None and len(string) > max_length:
        raise ExceptionValidation("{0} exceeds maximum length: {1}", 201, string, max_length)
    if min_length is not None and len(string) < min_length:
        raise ExceptionValidation("{0} doesn't meet minimum length: {1}", 202, string, min_length)


def check_format_string(string: Union[str, List[str]], is_binary: bool, length: int = None, alphabet: str = None,
                        min_length: int = None, max_length: int = None, encoding: str = None,
                        is_multiple_values: bool = False,
                        enums: list = None, restrictions: list = None):
    """
    Verifies if `number` complies with restrictions defined.

    Parameters
    ----------
    string: str
        String date to be verified

    is_binary: bool
        Boolean object, defining if string is Binary (encoded in Base 64) or Text

    length: int, optional
        Length of `string`, None if the constraint is not required (default is None)

    alphabet: str, optional
        List of allowed characters in `string`, None if the constraint is not required (default is None)

    min_length: int, optional
        Minimum length of `string`, None if the constraint is not required (default is None)

    max_length: int, optional
        Maximum length of `string`, None if the constraint is not required (default is None)

    encoding: str, optional
        Encoding of `string` (ie. `ASCII`, `latin-1`, ...), None if the constraint is not required (default is None)

    is_multiple_values: bool, optional
        Boolean Value stating if `string` can be a list of strings, None if the constraint is not required (default is False)

    enums: List, optional
        Allowed values for `string`, None if the constraint is not required (default is None)

    restrictions: List, optional
        Restrictions of disallowed characters (ie. *digits*, *letters*, *punctuation* and *whitespace*), None if the constraint is not required (default is None)

    Raises
    ----------
    ExceptionValidation(102), if string contains characters not defined in alphabet
    ExceptionValidation(300), if contains multiple values and shouldn't
    ExceptionValidation(400), if binary string isn't encoded in Base 64
    ExceptionValidation(401), if string isn't a string value
    ExceptionValidation(402), if string can't be encoded in the defined encoding
    ExceptionValidation(500), if string value isn't defined in given enum

    As well as the Exception thrown by `check_length` and `check_for_restrictions`
    """

    # Se não é de valores múltiplos e o tipo da string não é string
    if not is_multiple_values and type(string) is not str:
        raise ExceptionValidation("String {0} contains multiple values or isn't a string", 300, string)

    # Se string, então passar para lista de 1 string só, para tratar como uma lista de múltiplos valores (mas só 1 valor)
    if type(string) is str:
        string = [string]

    # Não ter carateres repetidos no alfabeto
    if alphabet is not None and (type(alphabet) is str or type(alphabet) is list):
        alphabet = set(alphabet)
    else:
        alphabet = None

    for s in string:

        try:
            check_length(s, length, min_length, max_length)
        except ExceptionValidation as e:
            raise e

        if is_binary:
            if type(s) is not str or not is_base64(s):
                raise ExceptionValidation("String encoding doesn't match Base 64", 400)

        else:
            if type(s) is not str:
                raise ExceptionValidation("String isn't a str object", 401)

            if encoding is not None:
                try:
                    s.encode(encoding)
                except UnicodeEncodeError or LookupError:
                    raise ExceptionValidation("String couldn't be encoded to {0}", 402, encoding)

            if enums is not None and type(enums) is list and s not in enums:
                raise ExceptionValidation("String {0} isn't defined in possible values: {1}", 500, s, enums)

            if restrictions is not None and type(restrictions) is list:
                try:
                    check_for_restrictions(s, set(restrictions))
                except ExceptionValidation as e:
                    raise e

            if alphabet is not None and not set(s).issubset(alphabet):
                raise ExceptionValidation(
                    "String {0} contains characters that aren't defined in possible values {1} such as {2}",
                    102, s, alphabet, list(set(s).difference(alphabet)))


def check_number(number: Union[int, float], is_nullable: bool = False, is_int: bool = True, __type_num: str = ""):
    """
    Verifies if `number` is a Integer or Float Object.

    Parameters
    ----------
    number: Union[int, float]
        number to be verified
    is_nullable: bool, optional
        True if number is Nullable, False, otherwise (default is False)
    is_int: bool, optional
        True if number must be an Integer, False, if must be a Float (default is None)
    __type_num: str, optional
        Specifies the number's identifier (default is "")

    Returns
    -------
    None
        if the number is a Nullable and None

    Raises
    ----------
    ExceptionValidation(600), if number must be an integer and isn't
    ExceptionValidation(601), if number isn't a number
    """

    if is_nullable and number is None:
        return

    if is_int and type(number) is not int:
        raise ExceptionValidation("{0}, {1}, isn't an integer", 600, __type_num, number)

    if type(number) is not int and type(number) is not float:
        raise ExceptionValidation("{0}, {1}, isn't a number", 601, __type_num, number)


def check_format_number(number: Union[int, float], is_int: bool, length: int = None,
                        lower_bound: Union[int, float] = None, upper_bound: Union[int, float] = None):
    """
    Verifies if `number` is an Integer or Float Object.

    Parameters
    ----------
    number: Union[int, float]
        number to be verified
    is_int: bool
        True if number must be an Integer, False, if must be a Float
    length: int, optional
        Length for number, ie. number of digits needed to write `number` paramater, None if the constraint is not required (default is None)
    lower_bound: Union[int, float], optional
        Minimum value for `number`, None if the constraint is not required (default is None)
    upper_bound: Union[int, float], optional
        Maximum value for `number`, None if the constraint is not required (default is None)

    Raises
    ----------
    ExceptionValidation(700), if number exceeds the defined length
    ExceptionValidation(701), if number is lower than the minimum value
    ExceptionValidation(702), if number is higher than the maximum value

    As well as the Exception thrown by `check_number`
    """
    try:
        number = int(number)
    except ValueError:
        raise ExceptionValidation("{0}, {1}, isn't an integer", 600, "Main Number", number)

    try:
        check_number(number, is_int=is_int, __type_num="Main Number")
        check_number(length, is_nullable=True, is_int=True, __type_num="Length")
        check_number(lower_bound, is_nullable=True, is_int=True, __type_num="Minimum Value")
        check_number(upper_bound, is_nullable=True, is_int=True, __type_num="Maximum Value")
    except ExceptionValidation as e:
        raise e

    if length is not None and number >= 10 ** length:
        raise ExceptionValidation("{0} exceeds length of {1}", 700, number, length)

    if lower_bound is not None and number < lower_bound:
        raise ExceptionValidation("{0} lower than the minimum value of {1}", 701, number, lower_bound)

    if upper_bound is not None and number > upper_bound:
        raise ExceptionValidation("{0} exceeds maximum value of {1}", 702, number, upper_bound)


def check_format_boolean(value: bool):
    """
    Verifies if `value` is a bool object.

    Parameters
    ----------
    value: bool
        Bool object to be verified

    Raises
    ----------
    ExceptionValidation(800), if value isn't a boolean object
    """

    if type(value) is not bool:
        raise ExceptionValidation("{0} isn't a boolean value", 800, value)


def check_format_date(date: str, is_full_date: bool, past_date: bool = False, future_date: bool = False, years_or_more: int = None, years_or_less: int = None):
    """
    Verifies if `string` defines a date following a given format.

    Parameters
    ----------
    date: str
        String date to be verified
    is_full_date: bool
        Boolean object, specifying if date follows "YYYY-M-D HH:MM:SS" (True) or "YY-M-D" (False)
    past_date: bool, optional
        Specifies if data must be a date in past (default is False)
    future_date: bool, optional
        Specifies if data must be a date in future (default is False)
    years_or_more: int, optional
        Specifies the minimum years between now and `date` (default is None)
    years_or_less: int, optional
        Specifies the maximum years between now and `date` (default is None)

    Raises
    ----------
    ExceptionValidation(900), if date isn't a string
    ExceptionValidation(901), date doesn't follow date format
    ExceptionValidation(902), if date must be a future date, but isn't
    ExceptionValidation(903), if date must be a past date, but isn't
    ExceptionValidation(904), date is lower than requested
    ExceptionValidation(905), date is higher than requested
    """

    if type(date) is not str:
        raise ExceptionValidation("{0} isn't a string", 900, date)

    if is_full_date:
        date_formatter = '%Y-%m-%d %H:%M:%S'
    else:
        date_formatter = '%Y-%m-%d'  # y para ser só 2 algarismos

    try:
        date_formatted = datetime.strptime(date, date_formatter).date()
    except ValueError:
        raise ExceptionValidation("{0} doesn't follow format {1}", 901, date, date_formatter)

    now = datetime.now().date()

    if past_date and (now - date_formatted).days < 0:
        raise ExceptionValidation("{0} represents a future date and it was requested a past date", 902, date)

    if future_date and (now - date_formatted).days > 0:
        raise ExceptionValidation("{0} represents a past date and it was requested a future date", 903, date)

    years_passed = now.year - date_formatted.year
    if now.month < date_formatted.month or (now.month == date_formatted.month and now.day < date_formatted.day):
        years_passed -= 1

    if years_or_more is not None and years_or_more >= 0 and years_or_more > years_passed:
        raise ExceptionValidation("{0} was {1} years ago, and should be at least {2}", 904, date, years_passed, years_or_more)
    elif years_or_less is not None and 0 <= years_or_less < years_passed:
        raise ExceptionValidation("{0} was {1} years ago, and should no more than least {2}", 905, date, years_passed, years_or_less)


def check_format_object(obj, functions_dict):
    for obj1 in obj:
        for item in obj1:
            func = functions_dict[item]

            if obj1[item] is not None and obj1[item] != []:
                func(obj1[item])
