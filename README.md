# Gnu Privacy Gremlin

Does all the little things.

## About Gremlin

## Features

Gremlin is fully featured in its implementation of gpg.

### The GPG Wrapper

Gremlin wraps the system `gpg` command, and parses an object of command line directives.

*Example of directives in json form*
```
conf = {
    "list-keys": True,
    "no-default-keyring": True,
    "keyring": second_keyring.gpg
}
```
### Custom Keyring Management

Gremlin can ingest a named yaml file and create a keyring, with keys, based on the contained directives.

### Encryption and Decryption

Coming Soon.
