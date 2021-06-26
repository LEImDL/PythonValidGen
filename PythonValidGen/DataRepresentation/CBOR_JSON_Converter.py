import cbor
from cbor import Tag
from cose.exceptions import CoseException
from cose.headers import StaticKey
from cose.keys import SymmetricKey, RSAKey, OKPKey, EC2Key, CoseKey
from cose.messages import Enc0Message, EncMessage, Mac0Message, MacMessage, Sign1Message, SignMessage, CoseMessage
from cose.messages.recipient import DirectEncryption, DirectKeyAgreement, KeyWrap, KeyAgreementWithKeyWrap
from cose.messages.signer import CoseSignature
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey, \
    EllipticCurvePublicNumbers, EllipticCurvePrivateNumbers
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey, RSAPublicNumbers, \
    RSAPrivateNumbers
from cryptography.hazmat.primitives.serialization import *


def cbor2json(cbor_obj):
    """
    Converts a `cbor object` into a `json object`.

    Parameters
    ----------
    cbor_obj: bytes
        `Cbor` object to be converted

    Returns
    ----------
    dict
        `Json` object represented in `dict` format
    """

    return cbor.loads(cbor_obj)


def json2cbor(json_obj):
    """
    Converts a `json object` into a `cbor object`.

    Examples
    --------
    Encoding a dict into CBOR, and decoding the previous result, resulting in equal objects
    enc = json2cbor({'1': 2})
    dec = cbor2json(enc)
    enc == dec # True

    Parameters
    ----------
    json_obj
        `Json` object to be converted

    Returns
    ----------
    bytes
        `Cbor` object represented in `bytes`
    """

    return cbor.dumps(json_obj)


__curve_names = {
    'prime256v1': 'P_256',
    'secp256r1': 'P_256',
    'secp384r1': 'P_384',
    'secp521r1': 'P_521',
    'secp256k1': 'SECP256K1',
    'ed25519': 'ED25519',
    'ed448': 'ED448',
    'x25519': 'X25519',
    'x448': 'X448',
}

__curve_sizes = {
    'P_256': 32,
    'P_384': 48,
    'P_521': 66,
    'SECP256K1': 32,
}


def load_key_from_file(public_path=None, private_path=None, password=None):
    """
    Loads a EC (PEM), RSA (PEM), or OKP (SSH) key into CoseKey

    Parameters
    ----------
    public_path
        Path to public key's file
    private_path
        Path to private key's file
    password
        Passphrase used to encrypt/decrypt key file

    Returns
    -------
    CoseKey Object, exactly RSAPublicKey, RSAPrivateKey, RSAPublicNumbers, RSAPrivateNumbers, OKPKey
    """
    pk, sk = None, None

    if public_path is not None:
        try:
            pk_tmp = load_pem_public_key(open(public_path, "rb").read())
            pn = pk_tmp.public_numbers()

            if isinstance(pk_tmp, EllipticCurvePublicKey):
                pn: EllipticCurvePublicNumbers
                crv = pn.curve.name
                crv_name = __curve_names[crv]
                crv_size = __curve_sizes[crv_name]
                y = pn.y.to_bytes(crv_size, byteorder='big')
                x = pn.x.to_bytes(crv_size, byteorder='big')

                pk = EC2Key(y=y, x=x, crv=crv_name)
            elif isinstance(pk_tmp, RSAPublicKey):
                pn: RSAPublicNumbers
                e = pn.e.to_bytes(512, byteorder='big')
                n = pn.n.to_bytes(512, byteorder='big')

                pk = RSAKey(e=e, n=n)
            else:
                return None
        except KeyError:
            return None
        except ValueError:

            try:
                pk_tmp = load_ssh_public_key(open(public_path, "rb").read(), backend=None)
                sk_tmp = load_ssh_private_key(open(private_path, "rb").read(), password)

                x = pk_tmp.public_bytes(Encoding.Raw, PublicFormat.Raw)
                d = sk_tmp.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                crv = pk_tmp.__module__.split(".")[-1]

                crv_name = __curve_names[crv]

                pk = OKPKey(x=x, crv=crv_name)
                sk = OKPKey(d=d, crv=crv_name)
            except KeyError:
                return None

    if private_path is not None:
        try:
            sk_tmp = load_pem_private_key(open(private_path, "rb").read(), password=password)
            sn = sk_tmp.private_numbers()

            if isinstance(sk_tmp, EllipticCurvePrivateKey):
                sn: EllipticCurvePrivateNumbers
                crv = sn.public_numbers.curve.name
                crv_name = __curve_names[crv]
                crv_size = __curve_sizes[crv_name]
                d = sn.private_value.to_bytes(crv_size, byteorder='big')

                sk = EC2Key(d=d, crv=crv_name)
            elif isinstance(sk_tmp, RSAPrivateKey):
                sn: RSAPrivateNumbers
                n = sn.public_numbers.n.to_bytes(512, byteorder='big')
                e = sn.public_numbers.e.to_bytes(512, byteorder='big')
                p = sn.p.to_bytes(512, byteorder='big')
                q = sn.q.to_bytes(512, byteorder='big')
                d = sn.d.to_bytes(512, byteorder='big')
                dmp = sn.dmp1.to_bytes(512, byteorder='big')
                dmq = sn.dmq1.to_bytes(512, byteorder='big')
                iqmp = sn.iqmp.to_bytes(512, byteorder='big')

                sk = RSAKey(e=e, n=n, d=d, p=p, q=q, dp=dmp, dq=dmq, qinv=iqmp)
            else:
                return None
        except ValueError:
            return None

    return pk, sk


def load_key(key):
    """
    Loads a cose key given another key.

    Examples
    --------
    Loading a public key in "key.key" file
        key = load_ssh_public_key(open("key.key", "rb").read())
        cosekey = load_key(key)

    Loading a private key in "key.key" file
        key = load_ssh_public_key(open("key.key", "rb").read(), password=password)
        cosekey = load_key(key)

    Parameters
    ----------
    key
        Key used to load other key

    Returns
    ----------
    cose_key
        Representing loaded cose key
    None
        If an `Error` has been encountered
    """

    if isinstance(key, bytes):
        cose_key = SymmetricKey(key)
    elif isinstance(key, EllipticCurvePublicKey):
        pn: EllipticCurvePublicNumbers = key.public_numbers()

        crv = pn.curve.name
        crv_name = __curve_names[crv]
        crv_size = __curve_sizes[crv_name]
        y = pn.y.to_bytes(crv_size, byteorder='big')
        x = pn.x.to_bytes(crv_size, byteorder='big')

        cose_key = EC2Key(y=y, x=x, crv=crv_name)
    elif isinstance(key, EllipticCurvePrivateKey):
        sn: EllipticCurvePrivateNumbers = key.private_numbers()
        crv = sn.public_numbers.curve.name
        crv_name = __curve_names[crv]
        crv_size = __curve_sizes[crv_name]
        d = sn.private_value.to_bytes(crv_size, byteorder='big')

        cose_key = EC2Key(d=d, crv=crv_name)
    elif isinstance(key, RSAPublicKey):
        pn: RSAPublicNumbers = key.public_numbers()

        e = pn.e.to_bytes(512, byteorder='big')
        n = pn.n.to_bytes(512, byteorder='big')

        cose_key = RSAKey(e=e, n=n)
    elif isinstance(key, RSAPrivateKey):
        sn: RSAPrivateNumbers = key.private_numbers()
        n = sn.public_numbers.n.to_bytes(512, byteorder='big')
        e = sn.public_numbers.e.to_bytes(512, byteorder='big')
        p = sn.p.to_bytes(512, byteorder='big')
        q = sn.q.to_bytes(512, byteorder='big')
        d = sn.d.to_bytes(512, byteorder='big')
        dmp = sn.dmp1.to_bytes(512, byteorder='big')
        dmq = sn.dmq1.to_bytes(512, byteorder='big')
        iqmp = sn.iqmp.to_bytes(512, byteorder='big')

        cose_key = RSAKey(e=e, n=n, d=d, p=p, q=q, dp=dmp, dq=dmq, qinv=iqmp)
    else:
        try:
            x = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            crv = key.__module__.split(".")[-1]
            crv_name = __curve_names[crv]
            cose_key = OKPKey(x=x, crv=crv_name)
        except AttributeError:
            try:
                d = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                crv = key.__module__.split(".")[-1]
                crv_name = __curve_names[crv]
                cose_key = OKPKey(d=d, crv=crv_name)
            except AttributeError:
                return None

    return cose_key


def __setup_signers(test_vectors, keys):
    signers = []

    i = 0
    for signer in test_vectors:
        cs = CoseSignature(phdr=signer['phdr'], uhdr=signer['uhdr'], key=None)
        cs.signature = signer['signature']

        key = load_key(keys[i])
        cs.key = key

        signers.append(cs)

        i += 1

    return signers


def __setup_direct_encryption_recipients(test_vectors, keys):
    recipients = []

    i = 0
    for recipient in test_vectors:

        if recipient['type'] == 'DirectKeyAgreement':
            key = CoseKey.decode(recipient['uhdr']['EPHEMERAL_KEY'])
            recipient['uhdr']['EPHEMERAL_KEY'] = key

            rcpt = DirectKeyAgreement(phdr=recipient['phdr'], uhdr=recipient['uhdr'])

            rcpt.key = key

            key2 = load_key(keys[i])
            rcpt.local_attrs = {StaticKey: key2}

        elif recipient['type'] == 'DirectEncryption':
            rcpt = DirectEncryption(phdr=recipient['phdr'], uhdr=recipient['uhdr'])
        elif recipient['type'] == 'KeyWrap':
            # Não testei
            rcpt = KeyWrap(phdr=recipient['phdr'], uhdr=recipient['uhdr'])
        elif recipient['type'] == 'KeyAgreementWithKeyWrap':
            # Não testei
            rcpt = KeyAgreementWithKeyWrap(phdr=recipient['phdr'], uhdr=recipient['uhdr'])
        else:
            continue

        recipients.append(rcpt)

        i += 1

    return recipients


def __json2cose(json_obj, keys):
    """
    Converts a `json object` into `cose object`.

    Parameters
    ----------
    json_obj
        `Json` object to be converted
    keys
        Keys used to encrypt object

    Returns
    ----------
    bytes
        Binary string representing encoded COSE object

    Raises
    ----------
    Exception
        If an unsupported `cbor tag` has been found
    """

    tag_id = json_obj['tag_id']

    if tag_id == 98:
        signers = __setup_signers(json_obj['signatures'], keys)

        msg = SignMessage(
            phdr=json_obj['phdr'],
            uhdr=json_obj['uhdr'],
            payload=json_obj['payload'],
            signers=signers
        )

        res = msg.encode()

    elif tag_id == 18:

        msg = Sign1Message(
            phdr=json_obj['phdr'],
            uhdr=json_obj['uhdr'],
            payload=json_obj['payload']
        )

        # Ver isto -> Ter vários tipos
        msg.key = load_key(keys)

        res = msg.encode()

    elif tag_id == 97:
        recipients = __setup_direct_encryption_recipients(json_obj['recipients'], keys)

        msg = MacMessage(
            phdr=json_obj['phdr'],
            uhdr=json_obj['uhdr'],
            payload=json_obj['payload'],
            key=None,
            recipients=recipients,
        )

        msg.key = load_key(keys)

        res = msg.encode()

    elif tag_id == 17:

        msg = Mac0Message(
            phdr=json_obj['phdr'],
            uhdr=json_obj['uhdr'],
            payload=json_obj['payload'],
            key=None,
        )

        msg.key = load_key(keys)

        res = msg.encode()

    elif tag_id == 96:
        recipients = __setup_direct_encryption_recipients(json_obj['recipients'], keys)

        msg = EncMessage(
            phdr=json_obj['phdr'],
            uhdr=json_obj['uhdr'],
            payload=json_obj['payload'],
            recipients=recipients,
        )

        res = msg.encode()

    elif tag_id == 16:

        msg = Enc0Message(
            phdr=json_obj['phdr'],
            uhdr=json_obj['uhdr'],
            payload=json_obj['payload'],
            key=None,
        )

        msg.key = load_key(keys)

        res = msg.encode()

    else:
        raise Exception("Unsupported CBOR TAG")

    return res


def __cose2json(cose_obj, keys):
    """
    Converts a `cose object` into `json object`.

    Parameters
    ----------
    cose_obj
        `Cose` object to be converted
    keys
        Keys used to decrypt object

    Returns
    ----------
    dict
        `Json` object represented in `dict` format

    Raises
    ----------
    Exception
        If an unsupported `cbor tag` has been found
    """

    cbor_tag: Tag = cbor.loads(cose_obj)

    tag_id = cbor_tag.tag
    cose_msg_ = CoseMessage.decode(cose_obj)

    phdr, uhdr = cose_msg_.phdr, cose_msg_.uhdr

    phdr_dict = {}
    for k, v in phdr.items():
        k_real = k.fullname if type(k) not in [str, bytes] else k
        v_real = v.fullname if type(v) not in [str, bytes] else v

        phdr_dict[k_real] = v_real

    uhdr_dict = {}
    for k, v in uhdr.items():
        k_real = k.fullname if type(k) not in [str, bytes] else k
        v_real = v.fullname if type(v) not in [str, bytes] else v

        uhdr_dict[k_real] = v_real

    if tag_id == 98:
        cose_msg: SignMessage = cose_msg_

        payload = cose_msg.payload
        signatures = cose_msg.signers

        real_signatures = []
        for signature in signatures:
            signature: CoseSignature

            phdr_dict_sig = {}
            for k, v in signature.phdr.items():
                k_real = k.fullname if type(k) not in [str, bytes] else k
                v_real = v.fullname if type(v) not in [str, bytes] else v

                phdr_dict_sig[k_real] = v_real

            uhdr_dict_sig = {}
            for k, v in signature.uhdr.items():
                k_real = k.fullname if type(k) not in [str, bytes] else k
                v_real = v.fullname if type(v) not in [str, bytes] else v

                uhdr_dict_sig[k_real] = v_real

            real_signatures.append(
                {"phdr": phdr_dict_sig, "uhdr": uhdr_dict_sig, "signature": signature.signature})

        res = {'phdr': phdr_dict, 'uhdr': uhdr_dict, 'payload': payload, 'signatures': real_signatures}

    elif tag_id == 18:
        cose_msg: Sign1Message = cose_msg_

        payload = cose_msg.payload
        signature = cose_msg.signature

        res = {'phdr': phdr_dict, 'uhdr': uhdr_dict, 'payload': payload, 'signature': signature}

    elif tag_id == 97:
        cose_msg: MacMessage = cose_msg_
        payload = cose_msg.payload
        auth_tag = cose_msg.auth_tag
        recipients = cose_msg.recipients

        # Ver recipients within recipients
        real_recipients = []
        for recipient in recipients:
            if isinstance(recipient, DirectEncryption):
                obj_type = "DirectEncryption"
            elif isinstance(recipient, DirectKeyAgreement):
                obj_type = "DirectKeyAgreement"
            elif isinstance(recipient, KeyWrap):
                obj_type = "KeyWrap"
            elif isinstance(recipient, KeyAgreementWithKeyWrap):
                obj_type = "KeyAgreementWithKeyWrap"
            else:
                return None

            phdr_dict_rec = {}
            for k, v in recipient.phdr.items():
                k_real = k.fullname if type(k) not in [str, bytes] else k
                v_real = v.fullname if type(v) not in [str, bytes] else v

                phdr_dict_rec[k_real] = v_real

            uhdr_dict_rec = {}
            for k, v in recipient.uhdr.items():
                k_real = k.fullname if type(k) not in [str, bytes] else k
                v_real = v.fullname if type(v) not in [str, bytes] else v

                uhdr_dict_rec[k_real] = v_real

            real_recipients.append(
                {"type": obj_type, "phdr": phdr_dict_rec, "uhdr": uhdr_dict_rec, "payload": recipient.payload})

        res = {'phdr': phdr_dict, 'uhdr': uhdr_dict, 'payload': payload, 'auth_tag': auth_tag,
               'recipients': real_recipients}

    elif tag_id == 17:
        cose_msg: Mac0Message = cose_msg_

        payload = cose_msg.payload
        auth_tag = cose_msg.auth_tag

        res = {'phdr': phdr_dict, 'uhdr': uhdr_dict, 'payload': payload, 'auth_tag': auth_tag}

    elif tag_id == 96:
        cose_msg: EncMessage = cose_msg_
        payload = cose_msg.payload
        recipients = cose_msg.recipients

        # Ver recipients within recipients
        real_recipients = []
        i = 0
        for recipient in recipients:
            if isinstance(recipient, DirectEncryption):
                obj_type = "DirectEncryption"
            elif isinstance(recipient, DirectKeyAgreement):
                obj_type = "DirectKeyAgreement"
            elif isinstance(recipient, KeyWrap):
                obj_type = "KeyWrap"
            elif isinstance(recipient, KeyAgreementWithKeyWrap):
                obj_type = "KeyAgreementWithKeyWrap"
            else:
                return None

            phdr_dict_rec = {}
            for k, v in recipient.phdr.items():
                k_real = k.fullname if type(k) not in [str, bytes] else k
                v_real = v.fullname if type(v) not in [str, bytes] else v

                phdr_dict_rec[k_real] = v_real

            uhdr_dict_rec = {}
            for k, v in recipient.uhdr.items():
                k_real = k.fullname if type(k) not in [str, bytes] else k

                v_real = v if type(v) is bytes else (
                    v.fullname if type(v) not in [RSAKey, OKPKey, EC2Key, SymmetricKey] else v.encode())

                uhdr_dict_rec[k_real] = v_real

            payload_rec = cose_msg.payload
            if type(keys) is list and len(keys) >= len(recipients):
                key = load_key(keys[i])
                recipient.key = key

                payload = payload_rec = cose_msg.decrypt(recipient)
            i += 1

            real_recipients.append(
                {"type": obj_type, "phdr": phdr_dict_rec, "uhdr": uhdr_dict_rec, "payload": payload_rec})

        res = {'phdr': phdr_dict, 'uhdr': uhdr_dict, 'payload': payload, 'recipients': real_recipients}

    elif tag_id == 16:
        cose_msg: Enc0Message = cose_msg_
        payload = cose_msg.payload

        if type(keys) is bytes:
            cose_msg.key = load_key(keys)
            payload = cose_msg.decrypt()

        res = {'phdr': phdr_dict, 'uhdr': uhdr_dict, 'payload': payload}

    else:
        raise Exception("Unsupported CBOR TAG")

    res = {**{'tag_id': tag_id}, **res}

    return res


def sign(payload, phdr: dict, uhdr: dict, key):
    """
    Sign a `json object` and return an equivalent `cose object`.

    Parameters
    ----------
    payload
        `JSON` object to be signed
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
        If an invalid combination of headers has been found, or wrong key type
    """

    msg = Sign1Message(
        phdr=phdr,
        uhdr=uhdr,
        payload=json2cbor(payload))

    msg.key = load_key(key)
    return msg.encode()


def mac(payload, phdr, uhdr, key):
    """
    Generates an Hash of a `json object` and return an equivalent `cose object`.

    Parameters
    ----------
    payload
        `JSON` object to be hashed
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
        If an invalid combination of headers has been found or wrong key type
    """

    msg = Mac0Message(
        phdr=phdr,
        uhdr=uhdr,
        payload=json2cbor(payload))

    msg.key = load_key(key)
    return msg.encode()


def enc(payload, phdr, uhdr, key):
    """
    Encrypts a `json object` and return an equivalent `cose object`.

    Parameters
    ----------
    payload
        `JSON` object to be encrypted
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
        If an invalid combination of headers has been found or wrong key type
    """

    msg = Enc0Message(
        phdr=phdr,
        uhdr=uhdr,
        payload=json2cbor(payload))

    msg.key = load_key(key)

    return msg.encode()


def decode_cose(cose_obj, key):
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
    Union[bytes, dict]
        Representation of JSON object

    Raises
    ----------
    Exception
        If an invalid combination of headers has been found or wrong key type
    """

    cbor_tag: Tag = cbor.loads(cose_obj)

    tag_id = cbor_tag.tag
    cose_msg_ = CoseMessage.decode(cose_obj)

    if tag_id == 18:
        cose_msg: Sign1Message = cose_msg_
        cose_msg.key = load_key(key)

        if not cose_msg.verify_signature():
            return None

        payload = cose_msg.payload

    elif tag_id == 17:
        cose_msg: Mac0Message = cose_msg_
        cose_msg.key = load_key(key)

        if not cose_msg.verify_tag():
            return None

        payload = cose_msg.payload

    elif tag_id == 16:
        cose_msg: Enc0Message = cose_msg_
        cose_msg.key = load_key(key)

        try:
            payload = cose_msg.decrypt()
        except CoseException:
            return None

    else:
        raise Exception("Unsupported CBOR TAG")

    return cbor2json(payload)
