import json
from json.decoder import JSONDecodeError
from typing import Union, IO

import xmltodict

from PythonValidGen.DataRepresentation.Utils.Exceptions import FormatNotSupported, ContentNotLoaded, FileAndContentIncompatible
from PythonValidGen.DataRepresentation.CBOR_JSON_Converter import cbor2json, json2cbor, sign, mac, enc, decode_cose


class Document:
    """
    A class used to represent and process a document.

    Examples
    -------
    Loading a file JSON file
        specification_path = '../../JSON_Files/mDL_specification_prototype.json'

        document = Document(file=specification_path, extension="JSON")
        specification = document.content

    Loading a dict object
        s = {"document": [{"name": "Family Name", "string": {"is_binary": false, "encoding": "utf-8", "max_length": 150, "restrictions": ["punctuation", "digits"]}, "mandatory": true}]}
        document = Document(content=s)
        print(document.content)

    Encryption using COSE and comparing the result of the decryption with the original content
        key = load_ssh_public_key(open("key.key", "rb").read())
        cosekey = load_key(key)

        enc = document.enc({'ALG': 'A128GCM', 'IV': b'000102030405060708090a0b0c'}, {}, cosekey)
        dec = decoded_cose(enc)

        dec == document.content

    Methods
    -------
    to_cbor()
        Used to get file content in `cbor` format.
    content()
        Content getter.
    """

    def __init__(self, file: str = None, extension: str = "JSON", content: Union[dict, str, None] = None):
        """
        Saves information about a Document.

        Parameters
        ----------
        file: str, optional
            String object representing the name of the file (default is None)
        extension: str, optional
            String object representing the extension of the file (default is "JSON")
        content: Union[dict, str, None], optional
            Represents the content of the file (default is None)
        """

        if file is None and content is None:
            raise FileAndContentIncompatible("File and Content arguments are both undefined")

        if file is not None and content is not None:
            raise FileAndContentIncompatible("File and Content arguments are both defined")

        try:
            if content is not None and type(content) is str:
                content = json.loads(content)
        except JSONDecodeError:
            raise FormatNotSupported("Plain Text", " only supports JSON")

        if file is not None and extension == "CBOR":
            # noinspection PyTypeChecker
            self.__file: Union[None, IO] = open(file=file, mode="rb")
        elif file is not None:
            # noinspection PyTypeChecker
            self.__file: Union[None, IO] = open(file=file, mode="r")

        self.__content: Union[None, dict] = content
        self.__extension: str = extension

        self.__process()

    def __process(self) -> None:

        if self.__content is None:
            if self.__extension == "JSON":
                self.__content = json.loads(self.__file.read())  # , object_pairs_hook=list)
            elif self.__extension == "XML":
                self.__content = json.loads(json.dumps(xmltodict.parse(self.__file.read())))['root']
            elif self.__extension == "CBOR":
                self.__content = cbor2json(self.__file.read())
            else:
                raise FormatNotSupported(self.__extension)

    @property
    def content(self) -> Union[None, dict]:
        """
        Content getter. Returns file content in `json` format.

        Returns
        ----------
        Union[None, dict]
            `None` or a `dict` representing the document content
        """
        return self.__content

    def sign(self, phdr, uhdr, key):
        """
        Signs a `json object` and return an equivalent `cose object`.

        Parameters
        ----------
        phdr: dict
            Protected headers, dict with pairs of key, values of either plaintext or cose.headers object (and cose.algorithms, p.e.)
        uhdr: dict
            Unprotected headers, dict with pairs of key, values of either plaintext or cose.headers object (and cose.algorithms, p.e.)
        key: Union[bytes, _PUBLIC_KEY_TYPES*, _PRIVATE_KEY_TYPES*, _SSH_PUBLIC_KEY_TYPES**, _SSH_PRIVATE_KEY_TYPES**]
            Keys used to sign object
            * - From cryptography.hazmat._types.py
            ** - From cryptography.hazmat.primitives.serialization.ssh

        Returns
        ----------
        Union[bytes, dict]
            Representation of CBOR/COSE object

        Raises
        ----------
        Exception
            If an invalid combination of headers has been found or key type
        """

        return sign(self.content, phdr, uhdr, key)

    def mac(self, phdr, uhdr, key):
        """
        MACs a `json object` and return an equivalent `cose object`.

        Parameters
        ----------
        phdr: dict
            Protected headers, dict with pairs of key, values of either plaintext or cose.headers object (and cose.algorithms, p.e.)
        uhdr: dict
            Unprotected headers, dict with pairs of key, values of either plaintext or cose.headers object (and cose.algorithms, p.e.)
        key: Union[bytes, _PUBLIC_KEY_TYPES*, _PRIVATE_KEY_TYPES*, _SSH_PUBLIC_KEY_TYPES**, _SSH_PRIVATE_KEY_TYPES**]
            Keys used to sign object
            * - From cryptography.hazmat._types.py
            ** - From cryptography.hazmat.primitives.serialization.ssh

        Returns
        ----------
        Union[bytes, dict]
            Representation of CBOR/COSE object

        Raises
        ----------
        Exception
            If an invalid combination of headers has been found or key type
        """

        return mac(self.content, phdr, uhdr, key)

    def enc(self, phdr, uhdr, key):
        """
        Encrypts a `json object` and return an equivalent `cose object`.

        Parameters
        ----------
        phdr: dict
            Protected headers, dict with pairs of key, values of either plaintext or cose.headers object (and cose.algorithms, p.e.)
        uhdr: dict
            Unprotected headers, dict with pairs of key, values of either plaintext or cose.headers object (and cose.algorithms, p.e.)
        key: Union[bytes, _PUBLIC_KEY_TYPES*, _PRIVATE_KEY_TYPES*, _SSH_PUBLIC_KEY_TYPES**, _SSH_PRIVATE_KEY_TYPES**]
            Keys used to sign object
            * - From cryptography.hazmat._types.py
            ** - From cryptography.hazmat.primitives.serialization.ssh

        Returns
        ----------
        Union[bytes, dict]
            Representation of CBOR/COSE object

        Raises
        ----------
        Exception
            If an invalid combination of headers has been found or key type
        """
        return enc(self.content, phdr, uhdr, key)

    def to_cbor(self) -> bytes:
        """
        Used to get file content in `cbor` format.

        Returns
        ----------
        bytes
            Represent the content in `cbor`

        Raises
        ----------
        ContentNotLoaded
            If document content hasn't been loaded
        """
        if self.__content:
            return json2cbor(self.__content)
        else:
            raise ContentNotLoaded()

    @staticmethod
    def decoded_cose(cose_obj, key):
        """
        Decodes a `cose object` and returns equivalent `json object`.

        Parameters
        ----------
        cose_obj
            `Cose` object to be decoded
        key: Union[bytes, _PUBLIC_KEY_TYPES*, _PRIVATE_KEY_TYPES*, _SSH_PUBLIC_KEY_TYPES**, _SSH_PRIVATE_KEY_TYPES**]
            Keys used to sign object
            * - From cryptography.hazmat._types.py
            ** - From cryptography.hazmat.primitives.serialization.ssh

        Returns
        ----------
        None
            if an error occured
        Document
            containing the payload in `cose_obj`

        Raises
        ----------
        Exception
            If an invalid combination of headers has been found or wrong key type
        """
        content = decode_cose(cose_obj, key)

        if content is not None:
            return Document(content=content)
        else:
            return None
