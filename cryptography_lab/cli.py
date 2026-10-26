"""File encryption and hashing CLI; passwords are entered without echo."""
import argparse
import getpass
import sys
from pathlib import Path
from cryptography_lab.crypto import (MAX_BYTES, aes_encrypt, aes_decrypt, rsa_encrypt,
                                     rsa_decrypt, generate_rsa_keys, sha256)


def read_limited(path, limit=MAX_BYTES):
    with Path(path).open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Input exceeds the size limit.')
    return data


def write_new(path, data, secret=False):
    # Exclusive create: never overwrite an existing original or key.
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if secret else 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ['aes-encrypt', 'aes-decrypt', 'rsa-encrypt', 'rsa-decrypt']:
        command = commands.add_parser(name)
        command.add_argument('input')
        command.add_argument('output')
        if name.startswith('rsa'):
            command.add_argument('--key', required=True)
    keygen = commands.add_parser('rsa-keygen')
    keygen.add_argument('--private', default='private.pem')
    keygen.add_argument('--public', default='public.pem')
    digest = commands.add_parser('sha256')
    digest.add_argument('input')
    args = parser.parse_args()
    try:
        if args.command == 'sha256':
            import hashlib
            with Path(args.input).open('rb') as stream:
                print(hashlib.file_digest(stream, 'sha256').hexdigest())
            return 0
        if args.command == 'rsa-keygen':
            if Path(args.private).exists() or Path(args.public).exists():
                raise ValueError('A key output already exists. Choose new filenames.')
            if Path(args.private).resolve() == Path(args.public).resolve():
                raise ValueError('Private and public key paths must differ.')
            password = getpass.getpass('Private key password (12+ characters): ')
            if password != getpass.getpass('Confirm password: '):
                raise ValueError('Passwords do not match.')
            private, public = generate_rsa_keys(password)
            write_new(args.private, private, secret=True)
            write_new(args.public, public)
            print('Created encrypted private key and public key.')
            return 0
        data = read_limited(args.input, MAX_BYTES * 2 if args.command.endswith('decrypt') else MAX_BYTES)
        if args.command.startswith('aes'):
            password = getpass.getpass('Password (12+ characters): ')
            if args.command == 'aes-encrypt' and password != getpass.getpass('Confirm password: '):
                raise ValueError('Passwords do not match.')
            result = aes_encrypt(data, password) if args.command == 'aes-encrypt' else aes_decrypt(data, password)
        elif args.command == 'rsa-encrypt':
            result = rsa_encrypt(data, read_limited(args.key, 65536))
        else:
            result = rsa_decrypt(data, read_limited(args.key, 65536), getpass.getpass('Private key password: '))
        write_new(args.output, result, secret=args.command.endswith('decrypt'))
        print(f'Saved: {args.output}')
        return 0
    except (OSError, ValueError, TypeError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
