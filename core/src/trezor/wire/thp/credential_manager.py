from trezor import protobuf
from trezor.crypto import hmac
from trezor.messages import (
    ThpAuthenticatedCredentialData,
    ThpCredentialMetadata,
    ThpPairingCredential,
)
from trezor.wire import message_handler

if __debug__:
    from ubinascii import hexlify

    from trezor import log


def derive_cred_auth_key() -> bytes:
    from storage.device import get_cred_auth_key_counter, get_thp_secret

    # derive the key using SLIP-21 https://github.com/satoshilabs/slips/blob/master/slip-0021.md
    # the derivation path is m/"Credential authentication key"/(counter 4-byte BE)

    S = get_thp_secret()
    m = hmac(hmac.SHA512, key=b"Symmetric key seed", message=S).digest()
    label = b"Credential authentication key"
    cred_auth_node = hmac(hmac.SHA512, key=m[0:32], message=b"\x00" + label).digest()
    counter = get_cred_auth_key_counter()
    cred_auth_key = hmac(
        hmac.SHA512, key=cred_auth_node[0:32], message=b"\x00" + counter
    ).digest()[32:64]

    return cred_auth_key


def invalidate_cred_auth_key() -> None:
    from storage.device import increment_cred_auth_key_counter

    increment_cred_auth_key_counter()


def issue_credential(
    cred_auth_key: bytes,
    host_static_pubkey: bytes,
    credential_metadata: ThpCredentialMetadata,
) -> bytes:
    proto_msg = ThpAuthenticatedCredentialData(
        host_static_pubkey=host_static_pubkey,
        cred_metadata=credential_metadata,
    )
    authenticated_credential_data = _encode_message_into_new_buffer(proto_msg)
    mac = hmac(hmac.SHA256, cred_auth_key, authenticated_credential_data).digest()

    proto_msg = ThpPairingCredential(cred_metadata=credential_metadata, mac=mac)
    credential_raw = _encode_message_into_new_buffer(proto_msg)
    if __debug__:
        log.debug(__name__, "credential raw: %s", hexlify(credential_raw).decode())
    return credential_raw


def validate_credential(
    cred_auth_key: bytes,
    encoded_pairing_credential_message: bytes,
    host_static_pubkey: bytes,
) -> bool:
    expected_type = protobuf.type_for_name("ThpPairingCredential")
    if __debug__:
        log.debug(__name__, "Expected type: %s", str(expected_type))
        log.debug(
            __name__,
            "Encoded message %s",
            hexlify(encoded_pairing_credential_message).decode(),
        )
    credential = message_handler.wrap_protobuf_load(
        encoded_pairing_credential_message, expected_type
    )
    assert ThpPairingCredential.is_type_of(credential)
    proto_msg = ThpAuthenticatedCredentialData(
        host_static_pubkey=host_static_pubkey,
        cred_metadata=credential.cred_metadata,
    )
    authenticated_credential_data = _encode_message_into_new_buffer(proto_msg)
    mac = hmac(hmac.SHA256, cred_auth_key, authenticated_credential_data).digest()
    return mac == credential.mac


def _encode_message_into_new_buffer(msg: protobuf.MessageType) -> bytes:
    msg_len = protobuf.encoded_length(msg)
    new_buffer = bytearray(msg_len)
    protobuf.encode(new_buffer, msg)
    return new_buffer
