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
        from . import key
        from . import keyring
        from . import secure
        from . import crypt

        self.unacceptable_tags = ['help', 'command', 'precmd', 'homedir']
        self.speshul_tags = ['keyring', 'no-default-keyring']
        self.commands = { 'gpg': shutil.which('gpg'), 'gpgtar': shutil.which('gpgtar') }
        self.config = config
        self.keyservers = {}
        for keyserver in config['keyservers']:
            self.keyservers[keyserver['name']] = hkp4py.KeyServer(keyserver['url'])
    
    def __fetch__(self, search_term=False, key_id=False, raw=False, data=False, blob=False):

        if search_term:
            results = [ self.keyservers[keyserver].search(search_term) for keyserver in self.keyservers ]
        elif key_id:
            results = [ self.keyservers[keyserver].search('0x{}'.format(key_id), exact=True) for keyserver in self.keyservers ]
            
        if raw:
            return results
        
        for keys in results:
            if keys:
                for key in keys:
                    if key.keyid == key_id:
                        if data:
                            return key
                        if blob:
                            return key.key_blob.decode('utf8')
                    else:
                        continue

    def __tabulate__(self, data):
        fmt = self.config['table_format']
        headers = data.pop(0)
        print(tabulate.tabulate(data, headers=headers, tablefmt=fmt, showindex="always", maxcolwidths=[None, None]))

    def __run__(self, conf={}):
        """
        Parse an object containing directives and values to pass to the
        GPG executable found in the system path in a raw format. There is
        functionally no difference between invoking this and invoking gpg
        directly.
        """
        run_args_list = [ ['--' + key, conf[key]] for key in conf.keys() if key not in self.unacceptable_tags and key not in self.speshul_tags and conf[key] is not None and conf[key] is not True and conf[key] is not False ]
        run_args_flags = [ ['--' + key, conf[key]] for key in conf.keys() if key not in self.unacceptable_tags and key not in self.speshul_tags and conf[key] is True ]

        # Handle "Special" tags (tags that come _must_ come first)
        speshul_args_list = [ ['--' + key, conf[key]] for key in conf.keys() if key in self.speshul_tags and conf[key] is not None and conf[key] is not True and conf[key] is not False ]
        speshul_args_flags = [ ['--' + key, conf[key]] for key in conf.keys() if key in self.speshul_tags and conf[key] is True ]

        run_args = [ arg for args_pair in run_args_list for arg in args_pair ]
        run_flags = [ arg[0] for arg in run_args_flags ]
        speshul_args = [ arg for args_pair in speshul_args_list for arg in args_pair ]
        speshul_flags = [ arg[0] for arg in speshul_args_flags ]
        retval = {}
        retval['runcmd'] = [self.commands['gpg']]
        retval['runcmd'].extend(speshul_flags)
        retval['runcmd'].extend(speshul_args)
        retval['runcmd'].extend(run_flags)
        retval['runcmd'].extend(run_args)
        if "homedir" in conf.keys() and conf['homedir'] is not None:
            retval['runcmd'].insert(1, "--homedir %s"%(conf['homedir']))
        if "precmd" in conf.keys() and conf['precmd'] is not None:
            p = subprocess.Popen(conf['precmd'], stdout=subprocess.PIPE)
            s = subprocess.Popen(retval['runcmd'], stdin=p.stdout, stdout=subprocess.PIPE)
            retval['output'] = s.communicate()[0]
        else:
            s = subprocess.Popen(retval['runcmd'], stdout=subprocess.PIPE)
            retval['output'] = s.communicate()[0]
        
        return retval
#            if output:
#                print(output.decode('utf8'))

    def __tar__(self, conf={}):
        """
        Parse an object containing directives and values to pass to the
        GPG executable found in the system path in a raw format. There is
        functionally no difference between invoking this and invoking gpgtar
        directly.
        """
        run_args_list = [ ['--' + key, conf[key]] for key in conf.keys() if key not in self.unacceptable_tags and conf[key] is not None and conf[key] is not True and conf[key] is not False ]
        run_args_flags = [ ['--' + key, conf[key]] for key in conf.keys() if key not in self.unacceptable_tags and conf[key] is True ]
        self.run_args = [ arg for args_pair in run_args_list for arg in args_pair ]
        self.run_flags = [ arg[0] for arg in run_args_flags ]
        retval = {}
        retval['runcmd'] = [self.commands['gpgtar']]
        retval['runcmd'].extend(self.run_args)
        retval['runcmd'].extend(self.run_flags)
        if "precmd" in conf.keys() and conf['precmd'] is not None:
            p = subprocess.Popen(conf['precmd'], stdout=subprocess.PIPE)
            s = subprocess.Popen(retval['runcmd'], stdin=p.stdout, stdout=subprocess.PIPE)
            retval['output'] = s.communicate()[0]
        else:
            s = subprocess.Popen(retval['runcmd'], stdout=subprocess.PIPE)
            retval['output'] = s.communicate()[0]
        
        return retval

def new(config):
    return Gremlin(config)
