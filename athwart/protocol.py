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

from tryfer.trace import Trace, Annotation, Endpoint
from twisted.internet.protocol import DatagramProtocol

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


class AthwartServerProtocol(DatagramProtocol):
    """A bridge from Logstash events to Zipkin.

    JSON-formatted data is received via UDP for processing then sent to a
    Zipkin server via Scribe.
    """

    def __init__(self, monitor_message=None, monitor_response=None):
        self.monitor_message = monitor_message
        self.monitor_response = monitor_response

    def datagramReceived(self, data, (host, port)):
        """Process received data and store it locally."""
        if data == self.monitor_message:
            # Send the expected response to the
            # monitoring agent.
            return self.transport.write(
                self.monitor_response, (host, port))
        return self.transport.reactor.callLater(
            0, self.process, data)

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
                       int_or_none(msg.get("zipkin_trace_id")),
                       int_or_none(msg.get("zipkin_next_span_id")),
                       int_or_none(msg.get("zipkin_span_id")))

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
                       int_or_none(msg.get("zipkin_trace_id")),
                       int_or_none(msg.get("zipkin_span_id")),
                       int_or_none(parent_span_id))
        endpoint = Endpoint(msg["host"], 0, frontend)
        strace.set_endpoint(endpoint)
        strace.record(Annotation.server_recv(sr))
        strace.record(Annotation.string('http.uri', msg["http_request"]))
        strace.record(Annotation.string(
            'http.responsecode', msg["http_status_code"]))
        strace.record(Annotation.server_send(ss))
