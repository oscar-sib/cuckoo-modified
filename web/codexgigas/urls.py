# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from django.conf.urls import patterns, url
from codexgigas import views as codexgigas

urlpatterns = [
    url(r"^(?P<cluster_id>[-\w]+)/$", codexgigas.shared_indicators, name='shared_indicators'),
]
