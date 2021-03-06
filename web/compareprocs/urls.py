# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from django.conf.urls import patterns, url
from compareprocs import views

urlpatterns = [
    url(r"^(?P<left_sid>\d+)-(?P<left_pid>\d+)/(?P<right_sid>\d+)-(?P<right_pid>\d+)/$", views.both, name='compareprocs_both'),
]
