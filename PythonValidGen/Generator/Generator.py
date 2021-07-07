import os
from shutil import copy
from PythonValidGen.Utils.Exceptions import FileAlreadyExists, FileNotFound, DuplicatedFields

dir_path = os.path.dirname(__file__)


class Generator:
    """
    A class used to load a `specification` and create a Python file for validating documents.

    Examples
    -------
    Generating a python file to validate documents that follows structure defined in `specification_path`'s file, and checking if struture is valid
        specification_path = '../../JSON_Files/mDL_specification_prototype.json'
        schema_path = '../../JSON_Files/standard_format_prototype.json'

        document = Document(file=specification_path, extension="JSON")
        specification = document.content

        schema = Document(file=schema_path, extension="JSON")
        verifier = Verifier(schema.content)

        verifier.verify(specification)
        generator = Generator(specification, target_path)
        generator.main()

        print("File generated")

    Methods
    -------
    main()
        Creates a Python file capable of validating a document with `specification` loaded.
    """

    def __init__(self, specification: dict, target_filename: str):
        """
        Initializer that saves information about a `specification` (ie. document format), `dict` object, as well as the target's filepath.

        Parameters
        ----------
        specification : dict
            The format to be defined/followed
        target_filename : str
            Path to the generated file
        """

        self.__specification: dict = specification
        self.__target_path = target_filename
        self.__target_file = None

    def __check_duplicated_field(self):
        all_fields = [field['name'] for field in self.__specification['document']]

        if len(all_fields) != len(set(all_fields)):
            dup_fields = list(set([field for field in all_fields if all_fields.count(field) > 1]))
            raise DuplicatedFields(str(dup_fields).replace("[", "").replace("]", "").replace(", ", ","))

    def __process_all(self, field, type_field, function_name, num=''):
        value = field[type_field]
        self.__target_file.write(function_name + "(val{0}".format(num))

        for key, value in value.items():
            if type(value) is str:
                self.__target_file.write(", " + key + "='" + value + "'")
            else:
                self.__target_file.write(", " + key + "=" + str(value))

    def __process_all_object(self, field, i):
        value = field['my_object']
        self.__target_file.write('check_format_object(val{0}, {1}'.format('' if i == 0 else i - 1, '{'))

        for field in value:
            name = field['name']

            if 'my_object' in field:
                self.__target_file.write("'" + name + "': (lambda val{0}: ".format(i))
                self.__process_all_object(field, i + 1)

            else:
                self.__target_file.write("'" + name + "': (lambda val{0}: ".format(i))

                if 'string' in field:
                    self.__process_all(field, 'string', 'check_format_string', i)
                elif 'number' in field:
                    self.__process_all(field, 'number', 'check_format_number', i)
                elif 'boolean' in field:
                    self.__process_all(field, 'boolean', 'check_format_boolean', i)
                elif 'date' in field:
                    self.__process_all(field, 'date', 'check_format_date', i)

            self.__target_file.write(")), ")

        self.__target_file.write("}")

    def __create_file(self):
        if os.path.exists(self.__target_path):
            raise FileAlreadyExists(self.__target_path)
        try:
            copy(os.path.join(dir_path, "Templates", "template0.txt"), self.__target_path)
            self.__target_file = open(self.__target_path, "a")
        except FileNotFoundError:
            raise FileNotFound("template0.txt")

    def __generate_main_python_code(self):
        self.__target_file.write("    function_dict = {")

        for field in self.__specification['document']:
            name = field['name']

            if 'my_object' in field:
                self.__target_file.write("'" + name + "': lambda val: ")
                self.__process_all_object(field, 0)
            else:
                self.__target_file.write("'" + name + "': lambda val: ")

                if 'string' in field:
                    self.__process_all(field, 'string', 'check_format_string')
                elif 'number' in field:
                    self.__process_all(field, 'number', 'check_format_number')
                elif 'boolean' in field:
                    self.__process_all(field, 'boolean', 'check_format_boolean')
                elif 'date' in field:
                    self.__process_all(field, 'date', 'check_format_date')

            self.__target_file.write("),\n                     ")

        self.__target_file.write("}\n\n")

    def __get_mandatory_fields(self):
        self.__target_file.write("    mandatories = ")
        self.__target_file.write(
            str([field['name'] for field in self.__specification['document'] if field['mandatory']]))
        self.__target_file.write("\n")

    def __get_optional_fields(self):
        self.__target_file.write("    optionals = ")
        self.__target_file.write(
            str([field['name'] for field in self.__specification['document'] if not field['mandatory']]))
        self.__target_file.write("\n")

    def __finalize_file(self):
        try:
            template = open(os.path.join(dir_path, "Templates", "template1.txt"), "r")
        except FileNotFoundError:
            raise FileNotFound("template1.txt")

        self.__target_file.write(template.read())
        self.__target_file.close()

        template.close()

    def main(self):
        """
        Creates a Python file capable of validating a document with `specification` loaded.

        Raises
        ----------
        DuplicatedFields
            If `specification` is malformed with fields identified by the same name

        FileAlreadyExists
            If target file already exists

        FileNotFound
            If template files can't be found
        """

        self.__check_duplicated_field()

        self.__create_file()

        self.__get_mandatory_fields()
        self.__get_optional_fields()

        self.__generate_main_python_code()

        self.__finalize_file()


if __name__ == '__main__':
    from PythonValidGen.DataRepresentation.Document import Document
    from PythonValidGen.Verifier.Verifier import Verifier
    import sys
    import os

    argv = sys.argv
    argc = len(argv)

    json_paths = os.path.join(dir_path, "..", "..", "JSON_Files")

    if argc < 2:
        specification_path = os.path.join(json_paths, 'mDL_specification_prototype1.json')
    else:
        specification_path = argv[1]

    if argc < 3:
        schema_path = os.path.join(json_paths, 'standard_format_prototype.json')
    else:
        schema_path = argv[2]

    if argc < 4:
        target_path = './validator_example.py'
    else:
        target_path = argv[3]

    document = Document(file=specification_path, extension="JSON")
    _specification = document.content

    schema = Document(file=schema_path, extension="JSON")
    verifier = Verifier(schema.content)

    verifier.verify(_specification)
    generator = Generator(_specification, target_path)
    generator.main()

    print("File generated")
