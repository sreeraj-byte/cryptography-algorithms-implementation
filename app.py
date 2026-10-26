"""Standalone dashboard: python -m streamlit run app.py"""
from pathlib import Path
import streamlit as st
from cryptography_lab.crypto import (aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt, generate_rsa_keys, sha256, MAX_BYTES)

ROOT = Path(__file__).parent
st.set_page_config(page_title='Cryptography Algorithms Implementation', page_icon='🛡️', layout='wide')
st.caption('Codec Technologies • Cyber Security Internship Project')

def crypto_page():
    st.header('Cryptography Algorithms Implementation')
    st.write('Encrypt files with AES or RSA hybrid encryption, and inspect SHA-256 hashes.')
    algorithm = st.radio('Algorithm', ['AES-256-GCM', 'RSA hybrid', 'SHA-256'], horizontal=True)
    st.caption('Learning application. Use sample data and keep private keys and passwords confidential.')
    if algorithm == 'SHA-256':
        st.write('SHA-256 creates a fingerprint. It is one-way hashing, so it has no decrypt operation.')
        text = st.text_area('Text to hash', 'Cyber Security Internship')
        upload = st.file_uploader('Or upload a file (up to 10 MiB)', key='hash_upload')
        expected = st.text_input('Expected SHA-256 (optional)')
        if st.button('Calculate SHA-256'):
            data = upload.getvalue() if upload else text.encode('utf-8')
            if len(data) > MAX_BYTES:
                st.error('Use a file of 10 MiB or smaller.')
            else:
                digest = sha256(data)
                st.code(digest)
                if expected:
                    if expected.strip().lower() == digest:
                        st.success('Hash matches.')
                    else:
                        st.error('Hash does not match.')
        return
    if algorithm == 'RSA hybrid':
        st.write('AES encrypts the file; RSA-OAEP encrypts its fresh AES key. This supports files larger than a direct RSA message.')
        with st.expander('Generate RSA key pair', expanded=True):
            with st.form('keygen'):
                key_password = st.text_input('New private key password (12+ characters)', type='password')
                confirmation = st.text_input('Confirm private key password', type='password')
                generate = st.form_submit_button('Generate 2048-bit RSA keys')
            if generate:
                try:
                    if key_password != confirmation:
                        raise ValueError('Passwords do not match.')
                    st.session_state['rsa_keys'] = generate_rsa_keys(key_password)
                except (ValueError, TypeError) as error:
                    st.error(str(error))
            if 'rsa_keys' in st.session_state:
                private, public = st.session_state['rsa_keys']
                st.download_button('Download encrypted private key', private, 'private.pem', key='download_private')
                st.download_button('Download public key', public, 'public.pem', key='download_public')
                st.caption('Download both keys. They are retained only for this active dashboard session.')
    operation = st.radio('Operation', ['Encrypt', 'Decrypt'], horizontal=True)
    with st.form('crypto_operation'):
        upload = st.file_uploader('Input file (encrypted JSON envelope for decryption)', key='crypto_input')
        public_upload = private_upload = None
        password = ''
        if algorithm == 'RSA hybrid':
            if operation == 'Encrypt':
                public_upload = st.file_uploader('RSA public key PEM (or use generated key)', type=['pem'])
            else:
                private_upload = st.file_uploader('Encrypted RSA private key PEM (or use generated key)', type=['pem'])
        if algorithm == 'AES-256-GCM' or operation == 'Decrypt':
            password = st.text_input('Password (12+ characters)', type='password')
        confirm = st.text_input('Confirm AES password', type='password') if algorithm == 'AES-256-GCM' and operation == 'Encrypt' else None
        submitted = st.form_submit_button(f'{operation} file', type='primary')
    if submitted:
        st.session_state.pop('crypto_output', None)
        try:
            if upload is None:
                raise ValueError('Upload an input file first.')
            limit = MAX_BYTES if operation == 'Encrypt' else MAX_BYTES * 2
            if upload.size > limit:
                raise ValueError('Input is larger than the supported limit.')
            data = upload.getvalue()
            if algorithm == 'AES-256-GCM':
                if operation == 'Encrypt' and password != confirm:
                    raise ValueError('Passwords do not match.')
                result = aes_encrypt(data, password) if operation == 'Encrypt' else aes_decrypt(data, password)
            else:
                generated = st.session_state.get('rsa_keys')
                if operation == 'Encrypt':
                    pem = public_upload.getvalue() if public_upload else generated[1] if generated else None
                    if pem is None:
                        raise ValueError('Upload or generate a public key.')
                    result = rsa_encrypt(data, pem)
                else:
                    pem = private_upload.getvalue() if private_upload else generated[0] if generated else None
                    if pem is None:
                        raise ValueError('Upload or generate a private key.')
                    result = rsa_decrypt(data, pem, password)
            filename = 'encrypted.json' if operation == 'Encrypt' else 'decrypted.bin'
            st.session_state['crypto_output'] = (result, filename, f'{algorithm} / {operation} / {upload.name}')
        except Exception as error:
            st.error(f'Operation failed: {error}')
    if 'crypto_output' in st.session_state:
        data, filename, label = st.session_state['crypto_output']
        st.success(f'Completed: {label}')
        st.download_button('Download last result', data, filename, 'application/octet-stream')
    if st.button('Clear cryptography session data'):
        st.session_state.pop('crypto_output', None)
        st.session_state.pop('rsa_keys', None)
        st.rerun()

crypto_page()
