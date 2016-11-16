# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from math import sqrt

def worseheur_get_processname_iter(tree, pid):
    """ Gets the name of a process from its PID, searching a process tree """

    name = None
    for process in tree:
        if process["pid"] == pid:
            return process["name"]
        else:
            name = worseheur_get_processname_iter(process["children"], pid)
            if name:
                break
    return name
    
def worseheur_tree_to_pidlist_iter(tree):
    """ Transforms a process tree into the corresponding list of PIDs """

    pidlist = []
    for process in tree:
        pidlist.append(process["pid"])
        if len(process["children"]) > 0:
            pidlist += worseheur_tree_to_pidlist_iter(process["children"])
    return pidlist 

def normalise_score(malheur_score):
    """ Normalises a similarity score
        @return a natural number between 0 and 100
    """

    return int(((sqrt(2) - float(malheur_score)) * 100)/sqrt(2))

