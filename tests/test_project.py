import json
from pathlib import Path
import pytest
from cryptography_lab.crypto import (aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt, generate_rsa_keys, sha256)
PASSWORD = "test-password-2026!"
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('message', [b'', b'hello', 'తెలుగు security'.encode(), bytes(range(256))*100])
def test_aes_roundtrip(message):
    encrypted = aes_encrypt(message, PASSWORD)
    assert aes_decrypt(encrypted, PASSWORD) == message
    assert encrypted != aes_encrypt(message, PASSWORD)


def corrupt(envelope, field):
    import base64
    value = json.loads(envelope)
    raw = bytearray(base64.b64decode(value[field]))
    raw[0] ^= 1
    value[field] = base64.b64encode(raw).decode()
    return json.dumps(value).encode()


def test_aes_wrong_password_and_tamper():
    encrypted = aes_encrypt(b'secret', PASSWORD)
    with pytest.raises(ValueError):
        aes_decrypt(encrypted, 'wrong-password-2026')
    for field in ['nonce', 'salt', 'ciphertext']:
        with pytest.raises(ValueError):
            aes_decrypt(corrupt(encrypted, field), PASSWORD)


@pytest.fixture(scope='module')
def keys():
    return generate_rsa_keys(PASSWORD)


def test_rsa_hybrid_large_binary_roundtrip(keys):
    private, public = keys
    assert b'BEGIN ENCRYPTED PRIVATE KEY' in private
    message = bytes(range(256)) * 100
    encrypted = rsa_encrypt(message, public)
    assert rsa_decrypt(encrypted, private, PASSWORD) == message
    for field in ['wrapped_key', 'ciphertext', 'nonce']:
        with pytest.raises(ValueError):
            rsa_decrypt(corrupt(encrypted, field), private, PASSWORD)
    with pytest.raises(ValueError):
        rsa_decrypt(encrypted, private, 'wrong-password-2026')
    other_private, _ = generate_rsa_keys(PASSWORD)
    with pytest.raises(ValueError):
        rsa_decrypt(encrypted, other_private, PASSWORD)


@pytest.mark.parametrize('invalid', [b'{}', b'[]', b'invalid', b'{"version":2}'])
def test_malformed_envelopes(invalid):
    with pytest.raises(ValueError):
        aes_decrypt(invalid, PASSWORD)


def test_sha256_known_vector():
    assert sha256(b'abc') == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'


def test_short_password_and_size_limit():
    with pytest.raises(ValueError):
        aes_encrypt(b'hello', 'short')
    from cryptography_lab.crypto import MAX_BYTES
    with pytest.raises(ValueError):
        aes_encrypt(b'x'*(MAX_BYTES+1), PASSWORD)


def test_cli_refuses_overwrite(tmp_path):
    from cryptography_lab.cli import write_new
    target = tmp_path/'original.txt'
    target.write_bytes(b'original')
    with pytest.raises(FileExistsError):
        write_new(target, b'replacement')
    assert target.read_bytes() == b'original'


def test_cli_aes_and_rsa_workflows(tmp_path, monkeypatch, capsys):
    from cryptography_lab.cli import main
    import sys
    monkeypatch.setattr('getpass.getpass', lambda *args: PASSWORD)
    plain = tmp_path/'plain.txt'
    plain.write_bytes(b'CLI integration test\x00binary\xff')
    def run(*args):
        monkeypatch.setattr(sys, 'argv', ['crypto', *map(str, args)])
        assert main() == 0
    aes = tmp_path/'aes.json'
    restored = tmp_path/'restored.txt'
    run('aes-encrypt', plain, aes)
    run('aes-decrypt', aes, restored)
    assert restored.read_bytes() == plain.read_bytes()
    private, public = tmp_path/'private.pem', tmp_path/'public.pem'
    run('rsa-keygen', '--private', private, '--public', public)
    envelope, restored_rsa = tmp_path/'rsa.json', tmp_path/'restored-rsa.txt'
    run('rsa-encrypt', plain, envelope, '--key', public)
    run('rsa-decrypt', envelope, restored_rsa, '--key', private)
    assert restored_rsa.read_bytes() == plain.read_bytes()
    run('sha256', plain)
    assert sha256(plain.read_bytes()) in capsys.readouterr().out


def test_dashboard_rsa_keys_and_password_validation():
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_file(str(ROOT/'app.py')).run()
    next(r for r in app.radio if r.label == 'Algorithm').set_value('RSA hybrid').run()
    assert not app.exception
    next(t for t in app.text_input if t.label.startswith('New private')).set_value(PASSWORD)
    next(t for t in app.text_input if t.label.startswith('Confirm private')).set_value(PASSWORD)
    next(b for b in app.button if b.label == 'Generate 2048-bit RSA keys').click().run()
    assert not app.exception
    private, public = app.session_state['rsa_keys']
    assert b'ENCRYPTED PRIVATE KEY' in private and b'BEGIN PUBLIC KEY' in public

def test_standalone_hash_dashboard():
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_file(str(ROOT/'app.py')).run()
    next(r for r in app.radio if r.label == 'Algorithm').set_value('SHA-256').run()
    app.button[0].click().run()
    assert not app.exception
    assert app.code[0].value == sha256(b'Cyber Security Internship')
