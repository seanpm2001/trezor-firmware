from trezor import protobuf
from trezor.crypto import hmac
from trezor.messages import (
    ThpAuthenticatedCredentialData,
    ThpCredentialMetadata,
    ThpPairingCredential,
)
from trezor.wire import message_handler
from ubinascii import hexlify


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
    return credential_raw


def validate_credential(
    cred_auth_key: bytes,
    encoded_pairing_credential_message: bytes,
    host_static_pubkey: bytes,
) -> bool:
    expected_type = protobuf.type_for_name("ThpPairingCredential")
    print("Expected type:", expected_type)
    print("Encoded message", hexlify(encoded_pairing_credential_message).decode())
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
