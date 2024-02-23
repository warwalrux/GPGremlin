import os
import sys
import shutil

def destroyKeyring(gremlin, name):
    """
    Destroy keyring
    """
    target = os.path.join(gremlin.config['gpghome'], "{}.kbx".format(name))
    if os.path.isfile(target):
        os.remove(target)
            

def newKeyring(gremlin, name):
    """
    Create additional (read non-default) named keyrings
    from file
    """

    if os.path.isfile(os.path.join(gremlin.config['ringdir'], name + ".yml")):
        ring_data = yaml.load(open(os.path.join(gremlin.config['ringdir'], name + ".yml")), Loader=yaml.FullLoader)
    else:
        print("%s not found" %(os.path.join(gremlin.config['ringdir'], name + ".yml")))
        sys.exit(0)

    name = name + ".gpg"
    conf = {
        "no-default-keyring": True,
        "keyring": name,
        "fingerprint": True,
        "homedir": gremlin.config['gpghome']
    }
    # Create the new keyring
    gremlin._gpg_run(conf)
    
    for monitor in ring_data['monitors']:
        print("Finding key for: %s" %(monitor))
        key = gremlin.__fetchKey(monitor, ring_data['monitors'][monitor], blob=True)
        if not key:
            c = input("GPG key for {} not found. Continue?[Y]: ".format(monitor))
            if c != "Y":
                print("Exiting...")
                sys.exit(0)
        else:
            conf = {
                'import': True, 
                'precmd': ['echo', key],
                'no-default-keyring': True,
                'keyring': name,
            }
            gremlin._gpg_run(conf)
def exportKeyring(gremlin, keyring, filename=False):
    if not keyring:
        print("Provide a keyring(-k|--keyring)")
        sys.exit(1)
    conf = {
            'armor': True,
            'keyring': keyring,
            'export': True,
        }
    if filename:
        conf['output'] = filename

    return(gremlin.__run__(conf))

def listKeyrings(gremlin):
    retval = []
    for file in os.listdir(gremlin.config['gpghome']):
        if file.endswith('.kbx'):
            retval.append(str(file.strip('.kbx')))
    return retval

def listKeys(gremlin, keyring):
    conf = {
            #'homedir': gremlin.config['gpghome'],
            'no-default-keyring': True,
            'list-keys': True,
            'keyring': "{}.kbx".format(keyring),
        }

    return(gremlin.__run__(conf))

