import os

def encrypt(gremlin, infile, outfile=False, recips=False, recip_file=False):
    conf = {'sign': True}

    if outfile:
        conf['output'] = outfile

    if recips:
        conf['recipient'] = recips
        conf['encrypt'] = infile
        if os.path.isdir(infile):
            return(gremlin.__tar__(conf))

        if os.path.isfile(infile):
            conf['armor'] = True
            return(gremlin.__run__(conf))
    
    elif recip_file:
        if os.path.isdir(infile):
            conf['files-from'] = recip_file
            conf['encrypt'] = infile
            return(gremlin.__tar__(conf))

        if os.path.isfile(infile):
            conf['recipient-file'] = recip_file
            conf['encrypt'] = infile
            conf['armor'] = True
            return(gremlin.__run__(conf))
    
    else:
        print("Provide recipient email or recipient file")

def decrypt(gremlin, infile, outfile=False):
    conf = {}
    if outfile:
        conf['output'] = outfile

    conf['decrypt'] = infile

    if os.path.isdir(infile):
        return(gremlin.__tar__(conf))

    if os.path.isfile(infile):
        return(gremlin.__run__(conf))
