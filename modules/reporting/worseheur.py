# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os
import subprocess
import hashlib
import urllib
import random

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

#worse-dev
import json
import base64
import shutil
import tempfile
import logging
log = logging.getLogger()

from lib.cuckoo.common.utils import pretty_print_arg
from lib.cuckoo.common.compareprocs import normalise_score
from modules.processing.worseheur import Detailed

#TODO worse-dev
import pprint

# The following methods are strongly 'inspired' by the analogous methods in
# the Enhanced class, though since they are not being used atm I rather
# having my own so the can be slightly adapted at will.
def sanitize_file(filename):
    normals = filename.lower().replace('\\', ' ').split(' ')
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals[-4:-1]]
    return ' '.join(hashed_components)

def sanitize_reg(keyname):
    normals = keyname.lower().replace('\\', ' ').split(' ')
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals[-2:]]
    return ' '.join(hashed_components)

def sanitize_cmd(cmd):
    normals = cmd.lower().replace('"', '').replace('\\', ' ').replace('.', ' ').split(' ')
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals]
    return ' '.join(hashed_components)

def sanitize_generic(value):
    return hashlib.md5(value.lower()).hexdigest()[:8]

def sanitize_domain(domain):
    components = domain.lower().split('.')
    hashed_components = [hashlib.md5(comp).hexdigest()[:8] for comp in components]
    return ' '.join(hashed_components)

def sanitize_ip(ipaddr):
    components = ipaddr.split('.')
    class_c = components[:3]
    return (hashlib.md5('.'.join(class_c)).hexdigest()[:8] + " " +
        hashlib.md5(ipaddr).hexdigest()[:8])

def sanitize_url(url):
    # normalize URL according to CIF specification
    uri = url
    if ":" in url:
        uri = url[url.index(':')+1:]
    uri = uri.strip("/")
    quoted = urllib.quote(uri.encode('utf8')).lower()
    return hashlib.md5(quoted).hexdigest()[:8]


def create_header(calls, ttree, results):
    """ Creates a header for the report file """
    lines = []

    if results["target"]["category"] == "file":
        lines.append("# FILE")
        lines.append("# MD5: " + results["target"]["file"]["md5"])
        lines.append("# SHA1: " + results["target"]["file"]["sha1"])
        lines.append("# SHA256: " + results["target"]["file"]["sha256"])
        lines.append("# Traces: " + str(len(calls)))
        lines.append("# Thread Tree: " + json.dumps(ttree["ROOT"]))
    elif results["target"]["category"] == "url":
        lines.append("# URL")
        lines.append("# MD5: " + hashlib.md5(results["target"]["url"]).hexdigest())
        lines.append("# SHA1: " + hashlib.sha1(results["target"]["url"]).hexdigest())
        lines.append("# SHA256: " + hashlib.sha256(results["target"]["url"]).hexdigest())
        lines.append("# Traces: " + str(len(calls)))
        lines.append("# Thread Tree: " + json.dumps(ttree["ROOT"]))

    return lines


def mist_convert_detail(results):
    """ Produces the equivalent MIST traces from a sequence of calls.
        Information is pretty detailed so it properly characterizes the
        behavior of processes"""
    lines = {}
    open_handles = {}
    loaded_modules = {}
    mapped = {}
    ttrees = {}
    parser = Detailed()

    def detail_file_mv_cp(entry):
        ffrom = entry["data"]["from"]
        fto = entry["data"]["to"]
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_file(ffrom) + " " + sanitize_file(fto) +
            "|" + ffrom + " " + fto)

    def detail_file_download(entry):
        url = entry["data"]["url"]
        fto = entry["data"]["to"]
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_url(url) + " " + sanitize_file(fto) +
            "|" + url + " " + fto)

    def detail_file_default(entry):
        filename = entry["data"]["file"]
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_file(filename) + "|" + filename)

    def detail_file_open(entry):
        data = entry["data"]
        handle = data["handle"]
        name = data["file"]
        if entry["status"]:
            open_handles[handle] = name

        # do not include this event unless it is successfully creating a file
        if (not "disposition" in data or not entry["status"] or
            data["disposition"] in ["1","4"]):
            return None
        else:
            pretty = pretty_print_arg(None, None, "CreateDisposition",
                data["disposition"]).replace("|", " OR ")
            return (entry["object"] + " " + entry["event"] + "|" +
                sanitize_file(name) + "|" + name + " (" + pretty + ")")

    def detail_file_query(entry):
        data = entry["data"]
        if "handle" in data and data["handle"] == "0xffffffff":
            return (entry["object"] + " " + entry["event"] + "|SELF|SELF")
        else:
            return detail_file_default(entry)

    def detail_file(entry):
        if entry["event"] in ["move", "copy"]:
            return detail_file_mv_cp(entry)
        elif entry["event"] in ["download"]:
            return detail_file_download(entry)
        elif entry["event"] in ["open", "create"]:
            return detail_file_open(entry)
        if entry["event"] in ["query"]:
            return detail_file_query(entry)

        return detail_file_default(entry)

    def detail_dir(entry):
        dirname = entry["data"]["file"]
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_file(dirname) + "|" + dirname)

    def detail_sys(entry):

        # shall we remove the handle?
        if entry["event"] == "close":
            if entry["status"] and entry["data"]["handle"] in open_handles:
                del open_handles[entry["data"]["handle"]]
            return None

        return entry["object"] + " " + entry["event"] + "||"

    def detail_cmd(entry):
        cmd = entry["data"]["command"]
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_cmd(cmd) + "|" + cmd)

    def detail_device(entry):
        pretty_code = pretty_print_arg(None, None, "IoControlCode",
            entry["data"]["code"])
        if not pretty_code:
            pretty_code = entry["data"]["code"]
        else:
            pretty_code = pretty_code.replace("|", " OR ")

        name = entry["data"]["handle"]
        if name in open_handles:
            name = open_handles[name]

        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_generic(pretty_code) + " " + sanitize_file(name) + "|" +
            pretty_code + " " + name)

    def detail_process_aux_handle(handle):
        if handle in open_handles:
            ret = ("OPENED", open_handles[handle])
        elif handle == "0xffffffff":
            ret = ("SELF", "SELF")
        else:
            ret = (handle, handle)
        return ret

    def detail_process_terminate(entry):

        handle = detail_process_aux_handle(entry["data"]["handle"])
        if entry["status"]:
            if handle[0] == "OPENED":
                del open_handles[entry["data"]["handle"]]
            elif handle[0] == "SELF":
                if entry["pid"] in open_handles:
                    del open_handles[entry["pid"]]

        return (entry["object"] + " " + entry["event"] + "|" +
            handle[0] + " " + entry["data"]["code"] + "|" +
            handle[1] + " Code:" + entry["data"]["code"])

    def detail_process_exit(entry):

        if entry["pid"] in open_handles and entry["status"]:
            del open_handles[entry["pid"]]

        return (entry["object"] + " " + entry["event"] + "|" +
            entry["data"]["code"] + "|" + "Code:" + entry["data"]["code"])

    def detail_process_open(entry):
        data = entry["data"]
        pid = data["id"]
        handle = data["handle"]
        if entry["status"]:
            open_handles[handle] = pid

        return None

    def detail_process_create(entry):
        # FileName is empty but we have a cmd
        name = entry["data"]["file"]
        if not name and "cmd" in entry["data"]:
            name = entry["data"]["cmd"]

        handle = entry["data"]["handle"]
        if entry["status"]:
            open_handles[handle] = name

        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_file(name) + "|" + name)

    def detail_process_write(entry):
        handle = detail_process_aux_handle(entry["data"]["handle"])

        addr = entry["data"]["addr"]
        length = entry["data"]["length"]
        return (entry["object"] + " " + entry["event"] + "|" +
            handle[0] + " " + sanitize_generic(addr) + " " +
            sanitize_generic(length) + "|" +
            handle[1] + " BaseAddr: " + addr + " Length: " + length)

    def detail_process_read(entry):
        handle = detail_process_aux_handle(entry["data"]["handle"])

        addr = entry["data"]["addr"]
        return (entry["object"] + " " + entry["event"] + "|" +
            handle[0] + " " + sanitize_generic(addr) +  "|" +
            handle[1] + " BaseAddr: " + addr)

    def detail_process(entry):

        if entry["event"] == "exit":
            return detail_process_exit(entry)
        if entry["event"] == "terminate":
            return detail_process_terminate(entry)
        elif entry["event"] == "create":
            return detail_process_create(entry)
        elif entry["event"] == "open":
            return detail_process_open(entry)
        elif entry["event"] == "write":
            return detail_process_write(entry)
        elif entry["event"] == "read":
            return detail_process_read(entry)

        return None

    def detail_memory_allocate(entry):
        data = entry["data"]
        handle = detail_process_aux_handle(data["handle"])

        protect = pretty_print_arg(None, None, "Protection",
            data["protection"]).replace("|", " OR ")
        addr = data["addr"]
        size = data["size"]

        return (entry["object"] + " " + entry["event"] + "|" +
            handle[0] + " " + size + "  " + sanitize_generic(protect) + "|" +
            handle[1] + " BaseAddr:" + addr + " Size:" + size +
            " (" + protect + ")")

    def detail_memory_protect(entry):
        data = entry["data"]
        handle = detail_process_aux_handle(data["handle"])

        protect = pretty_print_arg(None, None, "Protection",
            data["protection"]).replace("|", " OR ")
        addr = data["addr"]
        size = data["size"]

        return (entry["object"] + " " + entry["event"] + "|" +
            handle[0] + " " + sanitize_generic(protect) + "|" +
            handle[1] + " BaseAddr:" + addr + " Size:" + size +
            " (" + protect + ")")

    def detail_memory(entry):
        if entry["event"] == "allocate":
            return detail_memory_allocate(entry)
        elif entry["event"] == "protect":
            return detail_memory_protect(entry)
        return None

    def detail_section_create(entry):
        data = entry["data"]
        file_handle = data["file"]
        handle = data["section"]

        if entry["status"]:
            if file_handle == "0x00000000":
                open_handles[handle] = "PAGING_FILE"
            elif file_handle in open_handles:
                open_handles[handle] = open_handles[file_handle]
            else:
                open_handles[handle] = "UNKNOWN_FILE"

        return None

    def detail_section_open(entry):
        data = entry["data"]
        if entry["status"]:
            handle = data["section"]
            open_handles[handle] = data["file"]
        return None

    def detail_section_map(entry):
        data = entry["data"]
        proc_handle = detail_process_aux_handle(data["process"])
        sect_handle = data["section"]
        name = open_handles[sect_handle] if sect_handle in open_handles else None

        protect_raw = data["protect"]
        protect = pretty_print_arg(None, None, "Win32Protect",
            protect_raw).replace("|", " OR ")

        addr = data["addr"]
        mapped[addr] = True

        if name:
            return (entry["object"] + " " + entry["event"] + "|" +
                proc_handle[0] + " " + sanitize_file(name) + " " +
                sanitize_generic(protect_raw) + "|" +
                proc_handle[1] + " BaseAddr:" + addr + " File:" + name +
                " (" + protect + ")")
        else:
            return (entry["object"] + " " + entry["event"] + "|" +
                proc_handle[0] + " " + sanitize_generic(protect_raw) + "|" +
                proc_handle[1] + " BaseAddr:" + addr + " Section:" +
                sect_handle + " (" + protect + ")")

    def detail_section_unmap(entry):
        handle = detail_process_aux_handle(entry["data"]["process"])

        addr = entry["data"]["addr"]
        size = entry["data"]["size"]

        s_addr = sanitize_generic(addr)
        if addr in mapped:
            s_addr = "MAPPED"
            del mapped[addr]

        return (entry["object"] + " " + entry["event"] + "|" +
            handle[0] + " " + s_addr + "|" +
            handle[1] + " BaseAddr:" + addr)

    def detail_section(entry):

        if entry["event"] == "create":
            return detail_section_create(entry)
        if entry["event"] == "open":
            return detail_section_open(entry)
        if entry["event"] == "map":
            return detail_section_map(entry)
        elif entry["event"] == "unmap":
            return detail_section_unmap(entry)
        else:
            return None

    def detail_thread_create(entry):

        if "id" in entry["data"]:
            ttree = ttrees[entry["pid"]]
            # Build up the thread tree
            ptid = entry["tid"]
            ctid = entry["data"]["id"]

            # Store the relation parent -> child
            if not ptid in ttree:
                ttree[ptid] = {"children":{}, "timestamp":entry["timestamp"]}
                ttree["ROOT"][ptid] = ttree[ptid]

            if not ctid in ttree:
                ttree[ctid] = {"children":{}, "timestamp":entry["timestamp"]}
            elif ctid in ttree["ROOT"]:
                del ttree["ROOT"][ctid]
            ttree[ptid]["children"][ctid] = ttree[ctid]

            if entry["status"]:
                open_handles[entry["return"]] = entry["data"]["id"]

            return (entry["object"] + " " + entry["event"] + "|TID|" +
                entry["data"]["id"])

        return entry["object"] + " " + entry["event"] + "||"

    def detail_thread_terminate(entry):
        handle = entry["data"]["handle"]

        tid = handle
        if handle in open_handles:
            tid = open_handles[handle]
            if entry["status"]:
                del open_handles[handle]
        return entry["object"] + " " + entry["event"] + "|TID|" + tid

    def detail_thread(entry):
        if entry["event"] == "create":
            return detail_thread_create(entry)
        elif entry["event"] == "terminate":
            return detail_thread_terminate(entry)
        else:
            return entry["object"] + " " + entry["event"] + "||"

    def detail_mutant(entry):
        name = entry["data"]["name"]
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_generic(name) + "|" + name)

    def detail_net(entry):

        name = entry["data"]["name"]

        # if close, update the index of handles
        if entry["event"] == "close":
            if entry["status"] and name in open_handles:
                del open_handles[name]
            # do not include
            return None

        # keep the name for connects
        elif entry["event"] == "connect" and entry["status"]:
            open_handles[entry["return"]] = name

        # do not include opens as output, but keep a reference
        elif entry["event"] == "open":
            if entry["status"]:
                open_handles[entry["return"]] = (entry["data"]["handle"], name)
            return None

        # there must be a previous handle for the InternetHandle and the request
        elif entry["event"] == "send":
            if name in open_handles:
                handle = open_handles[name]
                if len(handle) == 2 and handle[0] in open_handles:
                    # ServerName/Path
                    name = "" + open_handles[handle[0]] + handle[1]
                    name = base64.b64encode(name)
                    base64.b64decode(name)

        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_generic(name) + "|" + name)

    def detail_reg(entry):
        regkey = entry["data"]["regkey"]
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_reg(regkey) + "|" + regkey + " " +
            ("SUCCESS" if entry["status"] else "FAILED"))

    def detail_windowname(entry):
        clsname = entry["data"]["classname"]
        winname = entry["data"]["windowname"]
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_generic(clsname) + " " +
            sanitize_generic(winname) + "|" + clsname + " " + winname)

    def detail_winhook(entry):
        hid = entry["data"]["id"]
        phid = pretty_print_arg(None, None, "HookIdentifier", hid)
        if not phid:
            phid = hid
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_generic(phid) + "|"  + phid)

    def detail_library(entry):
        base = entry["data"]["base"]
        file_name = entry["data"]["file"]
        if base not in loaded_modules:
            loaded_modules[base] = file_name

        # Do not include it in the results
        return None

    def detail_service_open(entry):
        data = entry["data"]
        name = data["name"]
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_generic(name) + " " + data["access"] + "|" +
            name + " " + pretty_print_arg("services", None,
                "DesiredAccess", data["access"]).replace("|", " OR "))

    def detail_service_create(entry):
        data = entry["data"]
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_generic(data["name"]) + " " +
            sanitize_file(data["path"]) + "|" +
            data["name"] + " " + data["path"])

    def detail_service(entry):
        data = entry["data"]
        name = data["name"]

        if entry["event"] == "open":
            return detail_service_open(entry)

        elif entry["event"] == "create":
            return detail_service_create(entry)

        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_generic(name) + "|" + name)

    def detail_event(entry):
        name = entry["data"]["name"]
        return (entry["object"] + " " + entry["event"] + "|" +
            sanitize_file(name) + "|" + name)

    #
    # body of mist_convert_detail() starts
    #
    if "behavior" not in results:
        return None

    for process in results["behavior"]["processes"]:
        pid = process["process_id"]
        for call in process["calls"]:

            entry = parser.process_call(call)
            if not entry:
                continue

            entry["pid"] = pid

            # initialize the thread tree for this pid
            if pid not in ttrees:
                ttrees[pid] = {}
                ttrees[pid]["ROOT"] = {}

            line = None
            if entry["object"] in ["registry"]:
                line = detail_reg(entry)
            elif entry["object"] in ["library"]:
                line = detail_library(entry)
            elif entry["object"] in ["file"]:
                line = detail_file(entry)
            elif entry["object"] in ["dir"]:
                line = detail_dir(entry)
            elif entry["object"] in ["system"]:
                line = detail_sys(entry)
            elif entry["object"] in ["process"]:
                line = detail_process(entry)
            elif entry["object"] in ["command"]:
                line = detail_cmd(entry)
            elif entry["object"] in ["windowname"]:
                line = detail_windowname(entry)
            elif entry["object"] in ["device"]:
                line = detail_device(entry)
            elif entry["object"] in ["thread"]:
                line = detail_thread(entry)
            elif entry["object"] in ["mutant"]:
                line = detail_mutant(entry)
            elif entry["object"] in ["windowshook"]:
                line = detail_winhook(entry)
            elif entry["object"] in ["service"]:
                line = detail_service(entry)
            elif entry["object"] in ["dns"]:
                line = detail_net(entry)
            elif entry["object"] in ["net"]:
                line = detail_net(entry)
            elif entry["object"] in ["event"]:
                line = detail_event(entry)
            elif entry["object"] in ["section"]:
                line = detail_section(entry)
            elif entry["object"] in ["memory"]:
                line = detail_memory(entry)

            if line:
                tid = entry["tid"]

                # KLUDGE:include the TID at the end of the call as MIST lvl4
                line = line + "|" + tid

                # update the thread tree
                if tid not in ttrees[pid]:
                    ttrees[pid][tid] = {
                        "children":{},
                        "timestamp":entry["timestamp"]
                    }
                    # link it from the ROOT node
                    ttrees[pid]["ROOT"][tid] = ttrees[pid][tid]

                if pid not in lines:
                    lines[pid] = {}
                if tid not in lines[pid]:
                    lines[pid][tid] = []
                lines[pid][tid].append(line)

    # everything was so worthless...
    if len(lines) <= 0:
        return None

    # for each PID, a set of calls grouped by their TID
    merged = {}
    for pid, pevents in lines.iteritems():
        aux = []
        for tid,tevents in pevents.iteritems():
            aux += tevents
        # calls for every thread go into one single file but grouped together
        merged[pid] = create_header(lines[pid], ttrees[pid], results) + aux

    return merged

def load_clusters_file(clustersfile):
    """ Loads the results file generated by malheur's clustering """
    clusters = {}
    members = {}
    with open(clustersfile, "r") as clustersfile:
        for line in clustersfile:
            if line[0] == '#':
                    continue
            parts = line.strip().split(' ')
            clst = parts[1]
            if clst != "rejected":
                idm = parts[0][:-4]
                if clst not in clusters:
                    clusters[clst] = []
                addval = {}
                addval["id"] = idm
                addval["proto"] = parts[2][:-4]
                addval["distance"] = parts[3]
                addval["cluster"] = clst
                clusters[clst].append(addval)

                if idm not in members:
                    members[idm] = addval

    return (clusters, members)

def create_symlinks(basedir, reportsdir, clusters):
    """ Creates some useful symlinks that will enable searching through
        the results """

    # storage/worseheur/members and storage/worseheur/clusters
    membersdir = os.path.join(basedir, "members")
    if os.path.isdir(membersdir):
        shutil.rmtree(membersdir)
    os.makedirs(membersdir)

    clustersdir = os.path.join(basedir, "clusters")
    if os.path.isdir(clustersdir):
        shutil.rmtree(clustersdir)
    os.makedirs(clustersdir)

    for clst in clusters:

        # create the cluster dir
        cluster = os.path.join(clustersdir, clst)
        if not os.path.isdir(cluster):
            os.makedirs(cluster)
            # store some metadata about the cluster
            info_path = os.path.join(cluster, "INFO.txt")
            with open(info_path, "w") as info:
                info.write(clst)

        #TODO: Use subdirs to avoid overloading the FS
        for member in clusters[clst]:

            # a reference to this cluster from the members dir
            memberlink = os.path.join(membersdir, member["id"])
            if not os.path.islink(memberlink):
                os.symlink(cluster, memberlink)

            # a references from the cluster to the member
            memberincluster = os.path.join(cluster,member["id"])
            if not os.path.islink(memberincluster):
                memberfile = os.path.join(reportsdir, member["id"] + ".txt")
                os.symlink(memberfile, memberincluster)

def calculate_distances(basedir, cfgpath):
    """ Calculates the distances file for every cluster so we can tell how far
        members are from each other """

    clustersdir = os.path.join(basedir, "clusters")
    path, dirs, files = os.walk(clustersdir).next()

    # for every cluster
    for clustername in dirs:
        thiscluster = os.path.join(clustersdir, clustername)

        distancefile = os.path.join(thiscluster, "distances.txt")

        # KLUDGE: malheur does not properly work on sysmlinks, zips, tars,...
        tmppath = tempfile.mkdtemp()
        cpath, cdirs, cfiles = os.walk(thiscluster).next()
        for f in cfiles:
            shutil.copy(os.path.join(thiscluster, f), tmppath)

        try:
            tmp = os.path.join(tmppath, "distance.txt")
            cmdline = ["malheur", "-c", cfgpath, "-o", tmp, "distance", tmppath]
            run = subprocess.Popen(cmdline, stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            out, err = run.communicate()

            # replace previous distances with new results atomically
            os.rename(tmp, distancefile)

        except Exception as e:
            raise CuckooReportError("Failed to perform Malheur classification: %s" % e)

        # clean up
        shutil.rmtree(tmppath)

def calculate_near_clusters(basedir, cfgpath, avail_clst, avail_members):
    """ Calculates the distance among the existing clusters so we can suggest
        other near groups given a process
        @return a dictionary that associates each process to a sorted list of
        near clusters
    """
    outputfile = os.path.join(basedir, "protodist.txt." +
        hashlib.md5(str(random.random())).hexdigest())
    reportsdir = os.path.join(basedir, "reports")

    # run malheur protodist
    try:
        cmdline = ["malheur", "-c", cfgpath, "-o", outputfile, "protodist", reportsdir]
        run = subprocess.Popen(cmdline, stdout=subprocess.PIPE,
                               stdin=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        out, err = run.communicate()

        # replace previous file
        os.rename(outputfile, outputfile[:-33])
        outputfile = outputfile[:-33]

    except Exception as e:
        raise CuckooReportError("Failed to calculate prototypes: %s" % e)

    # process the file recently created
    with open(outputfile, "r") as distfile:

        pparts = {}
        ids = []

        # first, read all the IDs in the protodist file
        for line in distfile:
            if line[0] == '#':
                continue
            parts = line.strip().split(' ')
            ids.append(parts[0][:-4])
            pparts[parts[0][:-4]] = parts[2:]

        # now we know which ID corresponds to each column
        distances = {}
        for proto_a, parts in pparts.iteritems():
            i = 0
            clst_a = avail_members[proto_a]["cluster"]
            distances[proto_a] = []
            for score in parts:
                norm_score = normalise_score(float(score))

                proto_b = ids[i]
                i = i + 1
                if proto_a == proto_b:
                    continue

                if norm_score > 0:
                    # which is the cluster of this prototype?
                    clst_b = avail_members[proto_b]["cluster"]
                    # do not include references to A's cluster
                    if clst_b == clst_a:
                        continue

                    clst_size = len(avail_clst[clst_b])
                    distances[proto_a].append([norm_score, clst_b, proto_b,
                        clst_size])
            # list of near clusters is sorted in reverse order
            aux = sorted(distances[proto_a], key=lambda z:z[0], reverse=True)
            distances[proto_a] = aux

        # distances contains the nearest prototypes for each prototype
        ret = {}
        for idm, member in avail_members.iteritems():
            # each clustered member has now a list of near clusters
            ret[idm] = distances[member["proto"]]
    return ret

class Worseheur(Report):
    """ Performs some nice clustering of the processes extracted from the observed
        behavior.
    """

    def run(self, results):
        """Runs Worseheur processing
        @return: Nothing.  Results of this processing are obtained at an
        arbitrary future time.
        """
        if results["target"]["category"] in ["pcap"]:
            return

        basedir = os.path.join(CUCKOO_ROOT, "storage", "worseheur")
        cfgpath = os.path.join(CUCKOO_ROOT, "conf", "worseheur.conf")
        reportsdir = os.path.join(basedir, "reports")
        task_id = str(results["info"]["id"])
        outputfile = os.path.join(basedir, "worseheur.txt." +
            hashlib.md5(str(random.random())).hexdigest())

        try:
            os.makedirs(reportsdir)
        except:
            pass

        # translate the available calls into MIST
        mist = mist_convert_detail(results)
        if not mist:
            return

        # one file per process, with the following ID: <task_id> + "_" + <PID>
        for pid in mist.keys():
            with open(os.path.join(reportsdir,
                task_id + "-" + str(pid) + ".txt"), "w") as outfile:
                outfile.write("\n".join(mist[pid]) + "\n")

        # follow your dreams...
        try:
            cmdline = ["malheur", "-c", cfgpath, "-o", outputfile, "cluster", reportsdir]
            run = subprocess.Popen(cmdline, stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            out, err = run.communicate()
            for line in err.splitlines():
                if line.startswith("Warning: Discarding empty feature vector"):
                    badfile = line.split("'")[1].split("'")[0]
                    os.remove(os.path.join(reportsdir, badfile))

            # replace previous classification state with new results atomically
            os.rename(outputfile, outputfile[:-33])
            outputfile = outputfile[:-33]

        except Exception as e:
            raise CuckooReportError("Failed to perform Malheur classification: %s" % e)

        # generate some auxiliary artifacts
        try:
            clusters, members = load_clusters_file(outputfile)
            create_symlinks(basedir, reportsdir, clusters)
            calculate_distances(basedir, cfgpath)
        except Exception as e:
            raise CuckooReportError("Error when handling results: %s" % e)
            pass

        # Calculate, process and save the set of prototypes
        near = calculate_near_clusters(basedir, cfgpath, clusters, members)
        near_path = os.path.join(basedir, "near.txt")
        near_file = open(near_path, "w")
        near_file.write(json.dumps(near))
        near_file.close()
