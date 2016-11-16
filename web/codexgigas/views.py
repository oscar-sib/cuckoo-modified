# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os
import subprocess
import sys

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_safe
from django.contrib.auth.decorators import login_required

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.common.config import Config

from lib.cuckoo.common.constants import CUCKOO_ROOT

import requests
import json

#TODO
import pprint

MIN_FREQ = 30

# which reporting modules are enabled
enabledconf = dict()
confdata = Config("reporting").get_config()
for item in confdata:
    if confdata[item]["enabled"] == "yes":
        enabledconf[item] = True
    else:
        enabledconf[item] = False

# establish the DB connections
if enabledconf["mongodb"]:
    import pymongo
    results_db = pymongo.MongoClient(settings.MONGO_HOST,
        settings.MONGO_PORT)[settings.MONGO_DB]

if enabledconf["elasticsearchdb"]:
    from elasticsearch import Elasticsearch
    baseidx = Config("reporting").elasticsearchdb.index
    fullidx = baseidx + "-*"
    es = Elasticsearch(
             hosts = [{
                 "host": settings.ELASTIC_HOST,
                 "port": settings.ELASTIC_PORT,
             }],
             timeout = 60
         )

# Conditional decorator for web authentication
class conditional_login_required(object):
    def __init__(self, dec, condition):
	self.decorator = dec
	self.condition = condition
    def __call__(self, func):
	if not self.condition:
	    return func
	return self.decorator(func)

def request_metadata(sha1):
    """ Contacts CodexGigas to retrieve the metadata associated to a given
        sample
    """

    url = confdata["codexgigas"]['base'] + "/api/v1/metadata?file_hash=" + sha1
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

def include_value(key, value, hits):
    """ Computes the occurrence of a value and includes it into a set of
        hits
    """

    if not key in hits:
        hits[key] = {}

    if not value in hits[key]:
        hits[key][value] = 0

    hits[key][value] += 1

def process_dict_entries(entries, hits):
    """ Processes a dictionary to include its entries in a set of hits """
    if hits == None:
        hits = {}

    for key, value in entries.iteritems():
        if not key in hits:
            hits[key] = {}
        if value and not value in hits[key]:
            hits[key][value] = True

    return hits

def process_list_entries(entries, hits):
    """ Processes a list to include its elements in a set of hits """

    if hits == None:
        hits = {}

    for entry in entries:
        if not entry in hits:
            hits[entry] = True

    return hits

def merge_list_hits(hits, partial):
    """ Merges a partial set of hits read from a list into a bigger one """

    for value in partial:
        if value not in hits:
            hits[value] = 0
        hits[value] += 1

def merge_dict_hits(hits, partial):
    """ Merges a partial set of hits read from a dictionary into a bigger one """

    for key, values in partial.iteritems():
        if not key in hits:
            hits[key] = {}
        for value in values:
            if not value in hits[key]:
                hits[key][value] = 0
            hits[key][value] += 1

def calculate_shared(samples):
    """ Calculates which static values are shared across a set of samples
        @return a set of hits that accounts for the frequency of every value
    """

    # this will be progressively filled
    hits = {
        "resources" : {},
        "headers" : {
            "dos_header" : {},
            "file_header" : {},
            "optional_header" : {},
        },
        "strings" : {
            "domains" : {},
            "hidden_dlls" : {},
            "hidden_imports" : {},
            "interesting" : {},
            "ips" : {},
            "raw_strings" : {},
        },
        "sections" : {},
        "imports" : {
            "functions" : {},
            "lib"       : {},
        },
        "version" : {
            "fixed" : {},
            "string" : {},
            "info" : {},
        },
    }

    for sha1, sample in samples.iteritems():

        # Res entries
        aux = {}
        for entry in sample["particular_header"]["res_entries"]:
            process_dict_entries(entry, aux)
        merge_dict_hits(hits["resources"], aux)

        # Headers
        aux = process_dict_entries(
            sample["particular_header"]["headers"]["dos_header"], None)
        merge_dict_hits(hits["headers"]["dos_header"], aux)
        aux = process_dict_entries(
            sample["particular_header"]["headers"]["file_header"], None)
        merge_dict_hits(hits["headers"]["file_header"], aux)
        aux = process_dict_entries(
            sample["particular_header"]["headers"]["optional_header"], None)
        merge_dict_hits(hits["headers"]["optional_header"], aux)

        # Strings
        strings = sample["particular_header"]["strings"]
        if "domains" in strings:
            aux = process_list_entries(strings["domains"], None)
            merge_list_hits(hits["strings"]["domains"], aux)
        if "hidden_dll" in strings:
            aux = process_list_entries(strings["hidden_dll"], None)
            merge_list_hits(hits["strings"]["hidden_dlls"], aux)
        if "hidden_imports" in strings:
            aux = process_list_entries(strings["hidden_imports"], None)
            merge_list_hits(hits["strings"]["hidden_imports"], aux)
        if "interesting" in strings:
            aux = process_list_entries(strings["interesting"], None)
            merge_list_hits(hits["strings"]["interesting"], aux)
        if "ips" in strings:
            aux = process_list_entries(strings["ips"], None)
            merge_list_hits(hits["strings"]["ips"], aux)
        # Codexgigas does not support searching by this and it's quite noisy anyway
        #if "raw_strings" in strings:
        #    aux = process_list_entries(strings["raw_strings"], None)
        #    merge_list_hits(hits["strings"]["raw_strings"], aux)

        # Sections
        aux = {}
        for entry in sample["particular_header"]["sections"]:
            process_dict_entries(entry, aux)
        merge_dict_hits(hits["sections"], aux)

        # Imports
        aux_f = {}
        aux_l = {}
        for imp in sample["particular_header"]["imports"]:
            process_list_entries(imp["functions"], aux_f)
            lib = imp["lib"]
            if lib and not lib in hits:
                hits[lib] = True
        merge_list_hits(hits["imports"]["functions"], aux_f)
        merge_list_hits(hits["imports"]["lib"], aux_l)

        # Version
        version = sample["particular_header"]["version"]
        if "fixed_file_info" in version:
            aux = process_dict_entries(version["fixed_file_info"], None)
            merge_dict_hits(hits["version"]["fixed"], aux)
        if "string_file_info" in version:
            aux = process_dict_entries(version["string_file_info"], None)
            merge_dict_hits(hits["version"]["string"], aux)
        if "version_info" in version:
            aux = process_dict_entries(version["version_info"], None)
            merge_dict_hits(hits["version"]["info"], aux)

    return hits

def calculate_frequency(hits, total):
    """ Calculates the frequency of every element in a set of hits. It also
        filters out those values that only appear once, since they can never
        be relevant to characterize a family of samples
    """

    ret = {}
    for key, values in hits.iteritems():
        for value, n in values.iteritems():

            # 2 hits minimum for an element
            if n < 2:
                continue

            freq = float(n) / total;
            if not key in ret:
                ret[key] = []
            ret[key].append({"value":value, "freq":int(freq*100), "num":n,
                "relevant":False})

    return ret

def tag_relevant(hits, relevant):
    """ Tags certain hits as relevant. Irrelevant hits will not be highlighted
        even if they have a high frequency in an attempt to reduce noise
    """

    for key, entries in hits.iteritems():
        if not relevant or key in relevant:
            for entry in entries:
                entry["relevant"] = True

def filter_frequent(hits, threshold):
    """ Filters out hits whose frequency is not above a certain threshold """

    ret = {}
    for key, entries in hits.iteritems():
        for entry in entries:
            if entry["freq"] >= threshold:
                if key not in ret:
                    ret[key] = []
                ret[key].append(entry)
    return ret

def prune_results(hits, total):
    """ Prunes the shared hits to reduce as much noise as possible and to ensure
        only valuable information get shown
    """

    indicators = {}

    # Resources
    pruned = calculate_frequency(hits["resources"], total)
    pruned = filter_frequent(pruned, MIN_FREQ)
    tag_relevant(pruned, ["lang", "name", "sha1", "sublang", "type"])
    if pruned:
        indicators["resources"] = pruned

    # Sections
    pruned = calculate_frequency(hits["sections"], total)
    pruned = filter_frequent(pruned, MIN_FREQ)
    tag_relevant(pruned, ["name", "characteristics"])
    if pruned:
        indicators["sections"] = pruned

    # Imports
    pruned = calculate_frequency(hits["imports"], total)
    # we need to be more strict here -> threshold=50%
    pruned = filter_frequent(pruned, 50)
    tag_relevant(pruned, ["functions", "lib"])
    if pruned:
        indicators["imports"] = pruned

    # Version
    pruned = calculate_frequency(hits["version"]["fixed"], total)
    pruned = filter_frequent(pruned, MIN_FREQ)
    tag_relevant(pruned, ["ProductVersionMS", "FileVersionMS", "Signature"])
    if pruned:
        if not "version" in indicators:
            indicators["version"] = {}
        indicators["version"]["fixed"] = pruned
    pruned = calculate_frequency(hits["version"]["string"], total)
    pruned = filter_frequent(pruned, MIN_FREQ)
    tag_relevant(pruned, None)
    if pruned:
        if not "version" in indicators:
            indicators["version"] = {}
        indicators["version"]["string"] = pruned
    pruned = calculate_frequency(hits["version"]["info"], total)
    pruned = filter_frequent(pruned, MIN_FREQ)
    if pruned:
        if not "version" in indicators:
            indicators["version"] = {}
        indicators["version"]["info"] = pruned

    # Headers
    pruned = calculate_frequency(hits["headers"]["dos_header"], total)
    pruned = filter_frequent(pruned, MIN_FREQ)
    if pruned:
        if not "headers" in indicators:
            indicators["headers"] = {}
        indicators["headers"]["dos_header"] = pruned
    pruned = calculate_frequency(hits["headers"]["file_header"], total)
    pruned = filter_frequent(pruned, MIN_FREQ)
    if pruned:
        if not "headers" in indicators:
            indicators["headers"] = {}
        indicators["headers"]["file_header"] = pruned
    pruned = calculate_frequency(hits["headers"]["optional_header"], total)
    pruned = filter_frequent(pruned, MIN_FREQ)
    if pruned:
        if not "headers" in indicators:
            indicators["headers"] = {}
        indicators["headers"]["optional_header"] = pruned

    # Strings
    pruned = calculate_frequency(hits["strings"], total)
    pruned = filter_frequent(pruned, MIN_FREQ)
    if pruned:
        indicators["strings"] = pruned

    return indicators


def get_db_info(sid):
    """ Retrieves from the database some information about a task """
    ret = None
    if enabledconf["mongodb"]:
        ret = results_db.analysis.find_one({"info.id": int(sid)},
            {"target": 1, "info": 1, "malscore": 1, "malfamily": 1})

    if enabledconf["elasticsearchdb"]:
        ret = es.search(
                   index=fullidx,
                   doc_type="analysis",
                   q="info.id: \"%s\"" % sid
               )["hits"]["hits"][-1]["_source"]
    return ret


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def shared_indicators(request, cluster_id):
    """ Generates a view that includes the static indicators shared acrosss a
        family of samples
    """

    # worseheur must be enabled so clustering is available
    if not enabledconf["worseheur"]:
        return render(request, "error.html",
                      {"error": "Enable worseheur in order to user this feature"})

    # determine the cluster's dir
    base_worse = os.path.join(CUCKOO_ROOT, "storage", "worseheur")
    clst_path = os.path.join(base_worse, "clusters", cluster_id)
    if not os.path.isdir(clst_path):
        return render(request, "error.html",
                      {"error": "Wrong cluster ID"})

    # retrieve the info available for each member
    db_info = {}
    md = {}
    members = {}
    path, dirs, files = os.walk(clst_path).next()
    tasks = []
    for member in files:
        parts = member.split('-')

        if len(parts) != 2:
            continue

        sid = parts[0]
        tasks.append(sid)

        if not sid in db_info:
            db_info[sid] = get_db_info(sid)
            if not db_info[sid]:
                continue

        sha1 = db_info[sid]["target"]["file"]["sha1"]
        if not sha1 in md:
            md[sha1] = request_metadata(sha1)
            members[sha1] = db_info[sid]

    hits = calculate_shared(md)
    indicators = prune_results(hits, len(md))

    # keep the data about malware families
    malfamilies_idx = {}
    for key,member in members.iteritems():
        if "malfamily" in member and member["malfamily"]:
            malfamilies_idx[member["malfamily"]] = True
    malfamilies = []
    for key in malfamilies_idx:
        malfamilies.append(key)

    # sample hashes
    hashes = []
    for key,member in members.iteritems():
        hashes.append({"sha1": key, "id": member["info"]["id"]})

    # summary
    summary = {}
    summary["families"] = ', '.join(malfamilies)
    summary["n_samples"] = len(members)
    summary["n_tasks"] = len(tasks)
    summary["tasks"] = ', '.join(sorted(tasks,key=lambda z:int(z)))
    summary["hashes"] = hashes

    return render(request, "codexgigas/indicators.html",
                              {"summary" : summary, "indicators": indicators})
