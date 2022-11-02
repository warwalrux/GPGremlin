import hkp4py
import os
import shutil
import subprocess
import sys
import yaml
import argparse
import tabulate

class Gremlin(object):
    """
    Gnu Privacy Gremlin (gremlin)
    
    Platform independent keyring manager
    for Gnu Privacy Guard
    """
    def __init__(self, config):
        self.unacceptable_tags = ['help', 'command', 'precmd']
        self.command = shutil.which('gpg')
        self.config = config
        self.keyservers = {}
        for keyserver in config['keyservers']:
            self.keyservers[keyserver['name']] = hkp4py.KeyServer(keyserver['url'])

    def __fetchKey(self, search_term, key_id="", raw=False):
        results = [ self.keyservers[keyserver].search(search_term) for keyserver in self.keyservers ]
        if raw:
            return results
        
        for keys in results:
            if keys:
                for key in keys:
                    if key.key_length >= self.config['min_key'] and key.keyid == key_id:
                        return key.key_blob.decode('utf8')
                    else:
                        continue 
    
    def __printTable(self, data):
        fmt = "grid"
        headers = data.pop(0)
        print(tabulate.tabulate(data, headers=headers, tablefmt=fmt, showindex="always", maxcolwidths=[None, None]))

    def _gpg_run(self, conf={}):
        """
        Parse an object containing directives and values to pass to the
        GPG executable found in the system path in a raw format. There is
        functionally no difference between invoking this and invoking gpg
        directly.
        """
        run_args_list = [ ['--' + key, conf[key]] for key in conf.keys() if key not in self.unacceptable_tags and conf[key] is not None and conf[key] is not True and conf[key] is not False ]
        run_args_flags = [ ['--' + key, conf[key]] for key in conf.keys() if key not in self.unacceptable_tags and conf[key] is True ]
        self.run_args = [ arg for args_pair in run_args_list for arg in args_pair ]
        self.run_flags = [ arg[0] for arg in run_args_flags ]
        runcmd = [self.command]
        runcmd.extend(self.run_args)
        runcmd.extend(self.run_flags)
        if "precmd" in conf.keys() and conf['precmd'] is not None:
            p = subprocess.Popen(conf['precmd'], stdout=subprocess.PIPE)
            s = subprocess.Popen(runcmd, stdin=p.stdout, stdout=subprocess.PIPE)
            print(s.communicate()[0].decode('utf8'))
        else:
            s = subprocess.Popen(runcmd, stdout=subprocess.PIPE)
            print(s.communicate()[0].decode('utf8'))

    def newKeyring(self, name):
        """
        Create additional (read non-default) named keyrings
        from file
        """

        if os.path.isfile(os.path.join(self.config['ringdir'], name + ".yml")):
            ring_data = yaml.load(open(os.path.join(self.config['ringdir'], name + ".yml")), Loader=yaml.FullLoader)
        else:
            print("%s not found" %(os.path.join(self.config['ringdir'], name + ".yml")))
            sys.exit(0)

        name = name + ".gpg"
        conf = {
            "no-default-keyring": True,
            "keyring": name,
            "fingerprint": True,
        }
        # Create the new keyring
        self._gpg_run(conf)
        
        for monitor in ring_data['monitors']:
            print("Finding key for: %s" %(monitor))
            key = self.__fetchKey(monitor, ring_data['monitors'][monitor])
            if not key:
                c = input("GPG key for %s not found. Continue?[Y]: "%(monitor))
                if c != "Y":
                    print("Exiting...")
                    sys.exit(0)
            else:
                conf = {
                    'import': True, 
                    'precmd': ['echo', self.__fetchKey(monitor, ring_data['monitors'][monitor])],
                    'no-default-keyring': True,
                    'keyring': name,
                }
                self._gpg_run(conf)

    def searchKeys(self, search_term):
        """
        Search configured keyserver for 'search_term'
        """
        rows = [["host", "id", "creation date", "expiration date", "length", "identities"]]
        for keys in self.__fetchKey(search_term, raw=True):
            if keys:
                for key in keys:
                    if key.key_length >= self.config['min_key']:
                        rows.append([key.host, key.keyid, key.creation_date, key.expiration_date, key.key_length, "\n".join([ identity.uid for identity in key.identities ]) ])
        if len(rows) > 1: self.__printTable(rows)
        else: print("Nothing found!")

    def listKeys(self, name):
        """
        list keys in the named keyring
        """
        conf = {
            "list-keys": True,
            "no-default-keyring": True,
            "keyring": name + ".gpg"
        }
        print(self._gpg_run(conf))
