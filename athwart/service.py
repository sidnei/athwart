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

import getopt
import sys
import time
import ConfigParser

from twisted.application.internet import UDPServer
from twisted.application.service import MultiService
from twisted.python import usage, log
from twisted.application.service import Service
from twisted.internet import task
from athwart.protocol import AthwartServerProtocol


def accumulateClassList(classObj, attr, listObj,
                        baseClass=None, excludeClass=None):
    """Accumulate all attributes of a given name in a class hierarchy
    into a single list.

    Assuming all class attributes of this name are lists.
    """
    for base in classObj.__bases__:
        accumulateClassList(base, attr, listObj, excludeClass=excludeClass)
    if excludeClass != classObj:
        if baseClass is None or baseClass in classObj.__bases__:
            listObj.extend(classObj.__dict__.get(attr, []))


class OptionsGlue(usage.Options):
    """Extends usage.Options to also read parameters from a config file."""

    optParameters = [
        ["config", "c", None, "Config file to use."]]

    def __init__(self):
        parameters = []
        accumulateClassList(self.__class__, 'optParameters',
                            parameters, excludeClass=OptionsGlue)
        for parameter in parameters:
            if parameter[0] == "config" or parameter[1] == "c":
                raise ValueError("the --config/-c parameter is reserved.")

        self.overridden_options = []

        super(OptionsGlue, self).__init__()

    def opt_config(self, config_path):
        self['config'] = config_path

    opt_c = opt_config

    def parseOptions(self, options=None):
        """Obtain overridden options."""

        if options is None:
            options = sys.argv[1:]
        try:
            opts, args = getopt.getopt(options,
                                       self.shortOpt, self.longOpt)
        except getopt.error, e:
            raise usage.UsageError(str(e))

        for opt, arg in opts:
            if opt[1] == '-':
                opt = opt[2:]
            else:
                opt = opt[1:]
            self.overridden_options.append(opt)

        super(OptionsGlue, self).parseOptions(options=options)

    def postOptions(self):
        """Read the configuration file if one is provided."""
        if self['config'] is not None:
            config_file = ConfigParser.RawConfigParser()
            config_file.read(self['config'])

            self.configure(config_file)

    def overridden_option(self, opt):
        """Return whether this option was overridden."""
        return opt in self.overridden_options

    def configure(self, config_file):
        """Read the configuration items, coercing types as required."""
        for name, value in config_file.items(self.config_section):
            self._coerce_option(name, value)

        for section in sorted(config_file.sections()):
            if section.startswith("plugin_"):
                self[section] = config_file.items(section)

    def _coerce_option(self, name, value):
        """Coerce a single option, checking for overriden options."""
        # Overridden options have precedence
        if not self.overridden_option(name):
            # Options appends '=' when gathering the parameters
            if (name + '=') in self.longOpt:
                # Coerce the type if required
                if name in self._dispatch:
                    if isinstance(self._dispatch[name], usage.CoerceParameter):
                        value = self._dispatch[name].coerce(value)
                    else:
                        self._dispatch[name](name, value)
                        return
                self[name] = value


class AthwartOptions(OptionsGlue):
    """
    The set of configuration settings for the service.
    """

    optParameters = [
        ["scribe-host", "h", "127.0.0.1",
         "The host where the scribe collector is listening.", str],
        ["scribe-port", "p", 9410,
         "The port where the scribe collector is listening.", int],
        ["logstash-listen-port", "l", 8725,
         "The UDP port where we will listen for Logstash messages.", int],
        ["span-listen-port", "l", 8726,
         "The UDP port where we will listen for base64 Zipkin span.", int],
        ["monitor-message", "m", "athwart ping",
         "Message we expect from monitoring agent.", str],
        ["monitor-response", "o", "athwart pong",
         "Response we should send monitoring agent.", str],
        ["dump-mode", "d", 0,
         "Dump received traces"
         " before passing them to scribe.", int],
        ]

    def __init__(self):
        self.config_section = 'athwart'
        super(AthwartOptions, self).__init__()


class AthwartService(Service):

    def __init__(self, carbon_client, processor, flush_interval, clock=None):
        self.carbon_client = carbon_client
        self.processor = processor
        self.flush_interval = flush_interval
        self.flush_task = task.LoopingCall(self.flushProcessor)
        self.coop = task.Cooperator()
        if clock is not None:
            self.flush_task.clock = clock

    def flushProcessor(self):
        """Flush messages queued in the processor to Graphite."""
        start = time.time()
        interval = self.flush_interval
        flush = self.processor.flush

        def doWork():
            flushed = 0
            for metric, value, timestamp in flush(interval=interval):
                yield self.carbon_client.sendDatapoint(
                    metric, (timestamp, value))
                flushed += 1
            log.msg("Flushed total %d metrics in %.6f" %
                    (flushed, time.time() - start))

        self.coop.coiterate(doWork())

    def startService(self):
        self.flush_task.start(self.flush_interval / 1000, False)

    def stopService(self):
        if self.flush_task.running:
            self.flush_task.stop()


def createService(options):
    from tryfer.tracers import (
        DebugTracer,
        EndAnnotationTracer,
        ZipkinTracer)
    from twisted.internet import reactor
    from twisted.internet.endpoints import TCP4ClientEndpoint
    from scrivener import ScribeClient

    from athwart.processor import HAProxyProcessor, SpanProcessor

    root_service = MultiService()
    root_service.setName("athwart")

    tracers = []
    if options["dump-mode"]:
        tracers.append(EndAnnotationTracer(DebugTracer(sys.stdout)))

    client = ScribeClient(TCP4ClientEndpoint(
        reactor, options["scribe-host"], options["scribe-port"]))
    tracers.append(ZipkinTracer(client))

    haproxy_processor = HAProxyProcessor(tracers)
    logstash_input = AthwartServerProtocol(
        haproxy_processor,
        monitor_message=options["monitor-message"],
        monitor_response=options["monitor-response"])

    logstash_listener = UDPServer(options["logstash-listen-port"],
                                  logstash_input)
    logstash_listener.setServiceParent(root_service)

    span_processor = SpanProcessor(client)
    span_input = AthwartServerProtocol(
        span_processor,
        monitor_message=options["monitor-message"],
        monitor_response=options["monitor-response"])

    span_listener = UDPServer(options["span-listen-port"], span_input)
    span_listener.setServiceParent(root_service)

    return root_service
