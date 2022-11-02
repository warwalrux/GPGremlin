# Gnu Privacy Gremlin

Gremlin can search multiple configured keyservers to generate keyring files.

## Using Gremlin

Gnu Privacy Gremlin leverages a `pipenv` managed Python virtual enviromnent. To set up the pipenv, run:

`pipenv install`

### Running Gremlin

The Privacy Gremlin is invoked using the `gremlin` script: 

`pipenv run python3 gremlin`

## Features

### GPG Key search

Gremlin is capable of taking a search term and returing all of the keys on several key servers in an easy to read format.

`pipenv run python3 gremlin -s <SEARCH_TERM>`

```
+----+------------------------------+------------------------------------------+---------------------+-------------------+----------+-----------------------------------------------+
|    | host                         | id                                       | creation date       | expiration date   |   length | identities                                    |
+====+==============================+==========================================+=====================+===================+==========+===============================================+
|  0 | https://keyserver.ubuntu.com | EAC133B6F904404A                         | 2019-03-21 15:24:31 |                   |     4096 | Andrew Foulks <dfoulks@apache.org>            |
+----+------------------------------+------------------------------------------+---------------------+-------------------+----------+-----------------------------------------------+
|  1 | https://keyserver.ubuntu.com | C70B04130E01135B                         | 2019-03-22 08:21:59 |                   |     4096 | Andrew Foulks (work key) <dfoulks@apache.org> |
+----+------------------------------+------------------------------------------+---------------------+-------------------+----------+-----------------------------------------------+
|  2 | https://keys.openpgp.org     | 6547814F1305619989803CA8C70B04130E01135B | 2019-03-22 08:21:59 |                   |     4096 | Andrew Foulks (work key) <dfoulks@apache.org> |
+----+------------------------------+------------------------------------------+---------------------+-------------------+----------+-----------------------------------------------+
```

### The GPG Wrapper

Gremlin is fully featured in its implementation of gpg. it wraps the system `gpg` command as `_gpg_run`, and parses an object of command line directives.

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

a keyring file named `gremlin.yml` in the keyrings directory containing the following:

```
---
monitors:
  "dfoulks@apache.org": '6547814F1305619989803CA8C70B04130E01135B'
```

will generate a keyring named `gremlin.gpg` in ~/.gnupg/ containing the one key.
