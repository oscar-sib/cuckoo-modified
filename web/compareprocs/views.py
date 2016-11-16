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

import lib.cuckoo.common.compare as compare
from lib.cuckoo.common.config import Config

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.compareprocs import (worseheur_get_processname_iter,
    normalise_score)

from math import ceil

import base64
import json
import time
import random
import hashlib

enabledconf = dict()
confdata = Config("reporting").get_config()
for item in confdata:
    if confdata[item]["enabled"] == "yes":
        enabledconf[item] = True
    else:
        enabledconf[item] = False

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


def read_hint(path, token, top_n):
    """ Reads some information stored in the headers of a report """

    ret = None
    read = 0
    with open(path, "r") as rfile:
        for line in rfile:
            #only the first 5 lines
            if read >= top_n:
                break
            if line.strip().startswith(token):
                ret = line[line.index(token) + len(token):]
            read += 1
    return ret

def read_num_lines_hint(path):
    """ Tries to get the total number of lines from the headers """

    token = "# Traces: "
    hint = read_hint(path, token, 10)
    return int(hint) if hint else None

def read_thread_tree_hint(path):
    """ Loads the thread tree stored in the headers of a report file """

    token = "# Thread Tree: "
    tree_hint = read_hint(path, token, 10)
    return json.loads(tree_hint)

def count_num_lines(path):
    """ Goes over a whole report to count the number of lines it contains """

    ret = 0
    with open(path, "r") as rfile:
        for line in rfile:
            if line[0] != '#':
                ret += 1
    return ret

def rand_token():
    """ Generates a superfluous trace that can be included in reports with only
        one event
    """

    # HACK: this will be filtered out on visualization
    token = "%08x"%random.randrange(16**8)
    return "END TRACES|HACK %s|Superfluous event to avoid empty vectors\n"%token

def split_file_into_parts(idp, path, out_dir, part_len, name_len):
    """ Splits a process' report into different parts. One line per trace.
        Traces for different threads will be stored in different parts. Every
        part will have a maximum length defined by 'part_len'
    """

    pattern = "%s_%s-%0" + str(name_len) + "d"

    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    total = 0
    with open(path, "r") as rfile:
        current_tid = None
        for line in rfile:
            if line[0] != '#':

                # catch the tid of this specific call
                mist_split = line.strip().split('|')
                tid = mist_split[-1]

                # group calls by tid
                if not current_tid or current_tid != tid:

                    if current_tid:
                        if total == 1:
                            part.write(rand_token())
                        part.close()

                    current_tid = tid
                    total = 0
                    part_path = os.path.join(out_dir, pattern%(idp, tid, total))
                    part = open(part_path, "w")

                # calls with the same tid may be split across different parts
                part.write('|'.join(mist_split[:-1]) + "\n")
                total += 1
                if (total % part_len) == 0:
                    if total == 1:
                        part.write(rand_token())
                    part.close()
                    part_path = os.path.join(out_dir, pattern%(idp, tid, total))
                    part = open(part_path, "w")

        if current_tid:
            if total == 1:
                part.write(rand_token())
            part.close()

def load_thread_tree(pid):
    """ Loads the thread tree stored in the report's headers """

    basedir = os.path.join(CUCKOO_ROOT, "storage", "worseheur")
    reportsdir = os.path.join(basedir, "reports")
    path = os.path.join(reportsdir, pid + ".txt")

    return read_thread_tree_hint(path)

def create_datasets(id_a, id_b):
    """ Creates two different datasets within the file-system. Each dataset
        contains the parts generated for each process.
    """

    # min number of traces per part
    MIN_PART_LEN = 5
    # max number of parts. This will never be exceeded
    MAX_NUM_PARTS = 30

    basedir = os.path.join(CUCKOO_ROOT, "storage", "worseheur")
    reportsdir = os.path.join(basedir, "reports")

    # calculate the lengths for the datasets
    a_path = os.path.join(reportsdir, id_a + ".txt")
    b_path = os.path.join(reportsdir, id_b + ".txt")

    a_len = count_num_lines(a_path)
    b_len = count_num_lines(b_path)

    max_len = a_len if a_len > b_len else b_len
    name_len = len(str(max_len))

    # now calculate the configuration for this execution
    part_len = MIN_PART_LEN
    part_num = max_len/MIN_PART_LEN
    if part_num > MAX_NUM_PARTS:
        part_num = MAX_NUM_PARTS
        part_len = max_len/part_num

    # calculate the name for both dirs
    partsdir = os.path.join(basedir, "compare")
    compare_dir = os.path.join(partsdir, id_a + "_" + id_b)
    mirror = os.path.join(partsdir, id_b + "_" + id_a)

    #TODO
    # maybe this is not the first time these two elements are compared. Reuse!
    #if os.path.isdir(compare_dir):
    #    return compare_dir

    # create both
    if not os.path.isdir(compare_dir):
        os.makedirs(compare_dir)
        os.symlink(compare_dir, mirror)

    # split the files into chunks
    split_file_into_parts(id_a, a_path, os.path.join(compare_dir, "parts"),
        part_len, name_len)
    split_file_into_parts(id_b, b_path, os.path.join(compare_dir, "parts"),
        part_len, name_len)

    return compare_dir

def run_malheur(path):
    """ Executes malheur to calculate the distances inside a given dataset """

    d_path = os.path.join(path, "parts")
    outputfile = os.path.join(path, "distances.txt." +
        hashlib.md5(str(random.random())).hexdigest())
    cfgpath = os.path.join(CUCKOO_ROOT, "conf", "worseheur.conf")

    cmdline = ["malheur", "-c", cfgpath, "-o", outputfile, "distance", d_path]
    run = subprocess.Popen(cmdline, stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    out, err = run.communicate()

    # replace previous file
    os.rename(outputfile, outputfile[:-33])

#TODO
import pprint

def read_distances(id_a, id_b, compare_dir):
    """ Reads the distances calculated by malheur for a dataset made up
        of the parts of two different processes.
        @return a tuple with two lists, one per process. Each element of
        these lists associates a part of the process with those parts from
        the opposing processes that have a score higher than zero. Both lists
        are alphabetically sorted.
    """

    dist_file = os.path.join(compare_dir, "distances.txt")
    a_scores = {}
    b_scores = {}

    with open(dist_file, "r") as distfile:
        mparts = {}
        ids = []
        # first get the ID of each row
        for line in distfile:
            if line[0] == '#':
                continue
            parts = line.strip().split(' ')
            ids.append(parts[0])
            mparts[parts[0]] = parts[2:]

        for memb_a, parts in mparts.iteritems():
            if id_a in memb_a:
                i = 0
                for score in parts:
                    memb_b = ids[i]
                    # do not compare id_a vs id_a
                    if id_b in memb_b:
                        if memb_a not in a_scores:
                            a_scores[memb_a] = {}
                        if memb_b not in b_scores:
                            b_scores[memb_b] = {}

                        norm_score = normalise_score(float(score))
                        # discard irrelevant scores
                        if norm_score > 0:
                            a_scores[memb_a][memb_b] = norm_score
                            b_scores[memb_b][memb_a] = norm_score
                    i = i + 1

    return (sorted(a_scores.items()), sorted(b_scores.items()))

def read_calls(pid, file_id, compare_dir, calls_idx):
    """ Reads MIST traces stored in a part file
        @return a list of MIST traces read from a part file
    """

    tid, n = split_file_id(file_id)

    calls = []
    part_path = os.path.join(compare_dir, "parts", pid + "_" + file_id)
    with open(part_path, "r") as rfile:
        for line in rfile:
            lvls = line.strip().split('|')

            cid = lvls[0] + " " + lvls[1]

            # figure out the category of the trace
            category, event = lvls[0].split(' ')

            # HACK:
            if category == "net" and event == "send":
                body = (category, event, base64.b64decode(lvls[2]))
            # HACK:
            elif category == "END" and event == "TRACES":
                continue
            else:
                body = (category, event, lvls[2])

            if cid not in calls_idx:
                calls_idx[cid] = len(calls_idx)

            calls.append((
                {"cid": calls_idx[cid], "cat": category},
                body
            ))

    return calls

def split_part_id(part_id):
    """ Splits the ID of a part. This type of ids concatenate the id of the
        process and an id for the file.
    """
    return part_id.strip().split('_')

def split_file_id(part_id):
    """ Splits a file id, which is created by concatenating a thread id and
        a sequential number that relates to the number of traces stored
    """
    return part_id.strip().split('-')

def create_sequence(distances, compare_dir, calls_idx):
    """ Creates a sequence of parts to be included in the GUI
        @return a dictionary where each entry contains a sequence of
        traces for a single thread
    """

    sequence = {}
    size = len(distances)
    i = 0
    # for every part that has some similarity with the opposing parts
    for part_id, links in distances:

        pid, file_id = split_part_id(part_id)
        tid, n = split_file_id(file_id)

        part = {}
        part["id"] = file_id
        part["links"] = []
        max_score = 0
        max_links = []
        # a list of parts in the other process that are similar
        for link in links:
            score = links[link]
            l_pid, l_file_id = split_part_id(link)
            # only keep the most similar parts, ignore the others
            if score > max_score:
                max_score = score
                max_links = []
                max_links.append(l_file_id)
            elif score > 0 and score == max_score:
                max_links.append(l_file_id)

        part["links"] = max_links
        part["simscore"] = max_score
        part["height"] = 100 / size if i<(size -1) else int(ceil(float(100)/size))
        # read the proper traces for this part so they can be shown
        part["calls"] = read_calls(pid, file_id, compare_dir, calls_idx)

        if tid not in sequence:
            sequence[tid] = {}
            sequence[tid]["parts"] = []
        sequence[tid]["parts"].append(part)

        i += 1

    # height for each thread block as a percentage. indentation is initialised to 0
    i = 0
    for tid in sequence:
        height = float(len(sequence[tid]["parts"])) * 100 / size
        sequence[tid]["height"] =  int(height) if i<(size - 1) else int(ceil(height))
        sequence[tid]["lvl"] = 0
        i += 1

    return sequence


def timestamp_to_epoch(timestamp):
    """ Translates a timestamp as returned by other modules into the equivalent
        epoch
    """

    pattern = "%Y-%m-%d %H:%M:%S,%f"
    return int(time.mktime(time.strptime(timestamp, pattern)))

def threadtree_to_list(sequence, ttree, lvl):
    """ Recursively transforms a thread tree into a list of threads
        @return a tuple that includes a list of descendants and the maximum
        level reached while calculating them. Threads at the same level are
        sorted according to the timestamp of their first trace
    """

    max_lvl = lvl
    ret = []

    # first calculate epochs from the threads' timestamps
    tids = []
    for tid, node in ttree.iteritems():
        if tid not in sequence:
            continue
        epoch = timestamp_to_epoch(node["timestamp"])
        tids.append((epoch, tid, node))
    sorted_tids = sorted(tids, key=lambda z: z[0])

    # threads are now sorted by their timestamp
    for epoch, tid, node in sorted_tids:

        sequence[tid]["lvl"] = lvl
        ret.append((tid, sequence[tid]))

        if node["children"]:
            lst, max_rec = threadtree_to_list(sequence,
                node["children"], lvl + 1)
            if max_rec > max_lvl:
                max_lvl = max_rec
            ret += lst

    return (ret, max_lvl)

@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def both(request, left_sid, left_pid, right_sid, right_pid):
    """ Generates a view that allows to intuitively compare two different
        processes
    """

    # retrieve information about both processes
    if enabledconf["mongodb"]:
        leftres = results_db.analysis.find_one({"info.id": int(left_sid)},
            {"target": 1, "info": 1, "behavior.processtree": 1})
        rightres = results_db.analysis.find_one({"info.id": int(right_sid)},
            {"target": 1, "info": 1, "behavior.processtree": 1})

    if enabledconf["elasticsearchdb"]:
        leftres = es.search(
                   index=fullidx,
                   doc_type="analysis",
                   q="info.id: \"%s\"" % left_sid
               )["hits"]["hits"][-1]["_source"]
        rightres = es.search(
                    index=fullidx,
                    doc_type="analysis",
                    q="info.id: \"%s\"" % right_sid
                )["hits"]["hits"][-1]["_source"]

    try:
        # prepare the datasets (they might remain stored for future operations)
        id_a = left_sid + "-" + left_pid
        id_b = right_sid + "-" + right_pid
        compare_dir = create_datasets(id_a, id_b)
        #TODO
        #if not os.path.isfile(os.path.join(compare_dir, "distances.txt")):
        run_malheur(compare_dir)
        distances_a, distances_b = read_distances(id_a, id_b, compare_dir)
    except Exception as e:
        print(str(e))
        return render(request, "error.html",
                      {"error": "An error occurred"})

    calls_idx = {}

    # prepare the left procbars
    left = {}
    left["pid"] = left_pid
    left["pname"] = worseheur_get_processname_iter(
        leftres["behavior"]["processtree"], int(left_pid))
    left["sample"] = leftres
    seq = create_sequence(distances_a, compare_dir, calls_idx)
    tree = load_thread_tree(id_a)
    left["sequence"], max_lvl = threadtree_to_list(seq, tree, 0)
    left["blck_lvls"] = range(0, max_lvl + 1)

    # now the ones on the right
    right = {}
    right["pid"] = right_pid
    right["pname"] = worseheur_get_processname_iter(
        rightres["behavior"]["processtree"], int(right_pid))
    right["sample"] = rightres
    seq = create_sequence(distances_b, compare_dir, calls_idx)
    tree = load_thread_tree(id_b)
    right["sequence"], max_lvl = threadtree_to_list(seq, tree, 0)
    right["blck_lvls"] = range(0, max_lvl + 1)

    return render(request, "compareprocs/both.html",
                              {"left": left, "right": right})
