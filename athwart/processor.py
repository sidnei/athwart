# Copyright (C) 2013 Canonical Services Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import re
import json
import datetime

from twisted.python import log
from tryfer.trace import Trace, Annotation, Endpoint

EPOCH = datetime.datetime.utcfromtimestamp(0)
FE_OR_BE = re.compile("(balancer://)?([^/]+)")
SERVER_SUB = re.compile("[^a-z0-9_-]")
TS_FMT = '%d/%b/%Y:%H:%M:%S.%f'


def unix_time(dt):
    delta = dt - EPOCH
    return delta.total_seconds()


def unix_time_micro(dt):
    return unix_time(dt) * 1000.0 * 1000.0 + dt.microsecond


def int_or_none(val):
    if val is None:
        return None

    return int(val, 16)


def parse_date_micro(dt):
    return int(unix_time_micro(datetime.datetime.strptime(dt, TS_FMT)))


class HAProxyProcessor(object):
    """Receive Logstash-massaged HAProxy input and generate Zipkin traces."""

    def __init__(self, tracers):
        self.tracers = tracers

    def process(self, data):
        msg = json.loads(data)
        if msg["frontend_name"] == "haproxy_monitoring":
            return

        frontend = FE_OR_BE.search(msg["frontend_name"]).group(2)
        backend = FE_OR_BE.search(msg["backend_name"]).group(2)
        server = SERVER_SUB.sub("_", msg["server_name"])

        # Consider server received to be the accept_date plus the time to
        # receive request headers.
        accept = parse_date_micro(msg["accept_date"])
        request = int(msg["time_request"]) * 1000
        if request < 0:
            request = 0
        sr = accept + request

        ctrace = Trace(msg["http_verb"],
                       trace_id=int_or_none(msg.get("zipkin_trace_id")),
                       span_id=int_or_none(msg.get("zipkin_next_span_id")),
                       parent_span_id=int_or_none(msg.get("zipkin_span_id")),
                       tracers=self.tracers)

        # There's an assumption here and in the server endpoint that the 'host'
        # parsed by Logstash from the syslog message is the same host as the
        # service is running on.
        endpoint = Endpoint(msg["host"], 0, backend)
        ctrace.set_endpoint(endpoint)

        # For client sent we consider the time in queue plus backend connect
        # time (which is the time to get the SYN/ACK from the backend).
        queue = int(msg["time_queue"]) * 1000
        if queue < 0:
            queue = 0
        connect = int(msg["time_backend_connect"]) * 1000
        if connect < 0:
            connect = 0
        cs = sr + queue + connect
        ctrace.record(Annotation.client_send(cs))
        ctrace.record(Annotation.string('haproxy.backend.server_name', server))

        # Record response time in ms into an annotation since it doesn't fit
        # anywhere in zipkin.
        response = int(msg["time_backend_response"]) * 1000
        if response < 0:
            response = 0
        ctrace.record(Annotation.string("haproxy.backend.time",
                                        str(response)))
        ctrace.record(Annotation.string("haproxy.backend.queue",
                                        msg["backend_queue"]))

        # Apache sends the duration in microseconds already. For haproxy we
        # have to convert from ms.
        duration = int(msg["time_duration"])
        if msg["program"] == "haproxy":
            duration = duration * 1000

        if duration < 0:
            duration = 0

        # Assume client response time to be the same as the request duration
        # minus a microsecond, just to keep ordering.
        ss = sr + duration
        cr = ss - 1
        ctrace.record(Annotation.client_recv(cr))

        # The top-level span is generally Apache. We record the parent span id
        # as '-' there if the parent span id is missing so convert to None.
        parent_span_id = msg.get("zipkin_parent_span_id")
        if parent_span_id is not None and parent_span_id == "-":
            parent_span_id = None

        strace = Trace(msg["http_verb"],
                       trace_id=int_or_none(msg.get("zipkin_trace_id")),
                       span_id=int_or_none(msg.get("zipkin_span_id")),
                       parent_span_id=int_or_none(parent_span_id),
                       tracers=self.tracers)
        endpoint = Endpoint(msg["host"], 0, frontend)
        strace.set_endpoint(endpoint)
        strace.record(Annotation.server_recv(sr))
        strace.record(Annotation.string('http.uri', msg["http_request"]))
        strace.record(Annotation.string(
            'http.responsecode', msg["http_status_code"]))
        strace.record(Annotation.server_send(ss))


class SpanProcessor(object):
    """Receive base64-formatted Zipkin Span and forward via Scribe."""

    def __init__(self, scribe_client, category=None):
        self._scribe = scribe_client
        self._category = category or 'zipkin'

    def process(self, data):
        d = self._scribe.log(self._category, [data])
        d.addErrback(
            log.err,
            "Error sending trace to scribe category: {0}".format(
                self._category))
