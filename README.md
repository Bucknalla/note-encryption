# Notecard Encryption / Decryption Service

This service is used to encrypt and decrypt data from Notecard events.

## Prerequisites

- Python 3.10+
- OpenSSL (already installed on most operating systems)
- [Ngrok](https://ngrok.com/download)

## Generating encryption keys

```bash
./generate.sh
```

## Running the service

```bash
cd python
python3 main.py
```

## Tunnelling the service

```bash
ngrok http 4000
```
