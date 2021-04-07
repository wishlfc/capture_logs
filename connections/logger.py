#  $Id $

import __main__


class Logger:
    def __init__(self, loglevel='Info'):
        """ "WARN", "INFO", "DEBUG", "TRACE"
        """
        self._loglevel = loglevel

    def trace(self, msg):
        self._log(msg, "Trace")

    def debug(self, msg):
        self._log(msg, "Debug")

    def info(self, msg):
        self._log(msg, "Info")

    def warn(self, msg):
        self._log(msg, "Warn")

    def is_trace(self):
        return self._loglevel.upper() == 'TRACE'

    def log(self, msg, loglevel=None):
        self._log(msg, loglevel)

    def _log(self, msg, loglevel=None):
        loglevel = loglevel is None and self._loglevel or loglevel
        msg = msg.strip()
        if msg != '' and loglevel is not None:
            # Jufei 2019.03.11 added, try to not show the log from PetShell, log is show in CPC.
            # print '*%s* %s' % (loglevel.upper(), msg)
            pass


class FileLogger(Logger):
    def __init__(self, loglevel='Info'):
        """ "WARN", "INFO", "DEBUG", "TRACE"
        """
        import sys
        import os
        from datetime import datetime
        now_time = datetime.now()
        nowN = now_time.strftime("%Y-%m-%d-%H-%M-%S")
        filename = "ipamml-dump-%s.txt" % nowN
        abs_path = os.path.abspath(filename)
        sys.__stderr__.write("\nipamml Dump:%s\n" % abs_path)
        self.output = open(filename, 'w')

    def log(self, msg, level=None):
        self.output.write("[%s]%s\n" % (level, msg))
        self.output.flush()

    def close(self):
        self.output.close()


class FileDumper(object):

    def __init__(self):
        import sys
        import os
        from datetime import datetime
        now_time = datetime.now()
        nowN = now_time.strftime("%Y-%m-%d-%H-%M-%S")
        filename = "telnet-dump-%s.txt" % nowN
        abs_path = os.path.abspath(filename)
        sys.__stderr__.write("\nTelnet Dump:%s\n" % abs_path)
        self.output = open(filename, 'w')

    def write(self, c):
        self.output.write(c)
        self.output.flush()

    def close(self):
        self.output.close()


class DummyDumper(object):

    def __init__(self):
        """used for Robot debuger."""
        import __main__
        self.rdb = None
        if hasattr(__main__, "RDB_TELNET_HOOKER"):
            self.rdb = __main__.RDB_TELNET_HOOKER

    def write(self, c):
        if self.rdb is not None:
            self.rdb.write(c)

    def close(self):
        pass
