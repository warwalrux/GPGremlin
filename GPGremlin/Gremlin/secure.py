import os

def verify(gremlin, filename):
    conf = {}
    conf['verify'] = filename
    return(gremlin.__run__(conf))

def sign(gremlin, filename):
    conf = {}
    conf['output'] = "{}.sig".format(filename)
    conf['detach-sig'] = True
    conf['sign'] = filename
    return(gremlin.__run__(conf))
