# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os
import subprocess
import hashlib
import urllib
import random


from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

#worse-dev
import json
import logging
import requests

log = logging.getLogger()
cfg = Config("reporting")

#worse-dev
import pprint

class CodexGigax(Report):
    """ Uploads every sample to CodexGigas """

    def upload_file(self, url, path, name):
        """ Uploads a file to CodexGigax """
        files = {"file": (name, open(path, "rb"), "application/x-ms-dos-executable")}
        ret = requests.post(url, files=files)
        return ret

    def file_exists(self, sha1):
        """ Checks whether a given sample exists in CodexGigas """
        url = cfg.codexgigas.base + "/api/v1/metadata?file_hash=" + sha1
        ret = requests.get(url)
        return ret.status_code == 200

    def run(self, results):
        """ Connects to CodexGigas and uploads the sample if necessary """

        if results["target"]["category"] not in ["file"]:
            return

        sha1= results["target"]["file"]["sha1"]

        path = results["target"]["file"]["path"]
        name = results["target"]["file"]["name"]
        up_url = cfg.codexgigas.base + "/api/v1/file/add"

        try:
            if not self.file_exists(sha1):
                r = self.upload_file(up_url, path, name)
                if r.status_code != 200:
                    log.warning("Unable to upload sample (%s): %s", sha1, r.text)
                    return
        except Exception as e:
            raise CuckooReportError("Error while uploading a file: %s" % e)
