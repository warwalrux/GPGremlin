import sys
import struct

def searchKeys(gremlin, search_term):
    """
    Search configured keyserver for 'search_term'
    Print only.
    """
    rows = [["host", "id", "creation date", "expiration date", "length", "identities"]]
    for keys in gremlin.__fetch__(search_term, raw=True):
        if keys:
            for key in keys:
                if key.key_length >= gremlin.config['min_key']:
                    rows.append([key.host, key.keyid, key.creation_date, key.expiration_date, key.key_length, "\n".join([ identity.uid for identity in key.identities ]) ])
    if len(rows) > 1: gremlin.__tabulate__(rows)
    else: print("Nothing found!")

def exportKey(gremlin, key_id, output=None, keyring=None):
    """
    export individual keys from a keyring
    """
    if not key_id:
        #        key = gremlin.__fetch__(key_id, key_id=key_id, blob=True)
        print("use with -k <key>")
        sys.exit(1)
    else:
        conf = {}
        conf['armor'] = True
        if output:
            conf['output'] = output
        conf['export'] = key_id
        if keyring:
            conf['keyring'] = keyring
            conf['homedir'] = gremlin.config['gpghome']
        conf['no-default-keyring'] = True

    return(gremlin.__run__(conf))


def importKeyfile(gremlin, key_file=None):
    """
    import key from file
    """

    conf = {
            'import': key_file
        }
    return(gremlin.__run__(conf))

def recvKey(gremlin, key_id):
    """
    import key from keyserver (recv-key)
    """
    
def showKey(gremlin, key_id=None, key_file=None):
    """
    Search configured keyservers for key with id: key_id"
    """
    if key_id:
        key = gremlin.__fetch__(key_id, key_id=key_id, blob=True)
    if key_file:
        key = open(key_file, "rb").read()

    conf = {
        'show-keys': True,
        'precmd': ['echo', key],
        'with-fingerprint': True
    }
    return(gremlin.__run__(conf))
