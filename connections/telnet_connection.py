#  $Id $

from robot import utils, utils
import telnetlib
from .logger import Logger, FileDumper, DummyDumper, FileLogger
import re
try:
    import thread
except ImportError:
    import _thread
import os
import time
import six
import sys


def to_bytes(s):
    return s.encode('utf-8') if six.PY3 else s


def to_str(s):
    return str(s) if six.PY3 else s


def add_str(sa, sb):
    if type(sa) is str and type(sb) is str:
        return sa + sb
    elif type(sa) is bytes and type(sb) is bytes:
        return sa + sb
    elif type(sa) is str and type(sb) is bytes:
        return sa.encode('utf-8') + sb
    else:
        return sa + sb.encode('utf-8')


if os.name == 'java':
    from select import cpython_compatible_select as select
else:
    from select import select


class TelnetConnection(telnetlib.Telnet):

    def __init__(self, host, port, prompt, timeout="10sec", newline='CRLF'):
        port = port == '' and 23 or int(port)
        self._timeout = float(utils.timestr_to_secs(timeout))
        telnetlib.Telnet.__init__(self, host, port)
        self._prompt = None
        self.set_prompt(prompt)
        self._newline = newline.upper().replace('LF', '\n').replace('CR', '\r')
        self._loglevel = "INFO"
        self._log_buffering = False
        self._log_buffer = ""
        self._logger = Logger()
        self._pause = 3
        self.type = "TELNET"

        dump_telnet = os.getenv("DUMP_TELNET", "NO") == 'YES'
        self._dumper = dump_telnet and FileDumper() or DummyDumper()
        if os.getenv("DUMP_IPAMML", "NO") == 'YES':
            self._logger = FileLogger()

    def __str__(self):
        return str(self.host) + ":" + str(self.port) + " " + repr(self)

    def __del__(self):
        """Override Telnet.__del__ because it sometimes causes problems"""
        pass

    def open(self, host, port=0, *args):
        """Override Telnet.open set timeout of create connection!"""
        import socket
        self.eof = 0
        if not port:
            port = TELNET_PORT
        self.host = host
        self.port = port
        msg = "getaddrinfo returns an empty list"
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                self.sock = socket.socket(af, socktype, proto)
                self.sock.settimeout(self._timeout)
                self.sock.connect(sa)
            except socket.error as msg:
                if self.sock:
                    self.sock.close()
                self.sock = None
                continue
            break
        if not self.sock:
            raise socket.error(msg)

    def get_recv(self, length):
        time.sleep(self._pause)
        try:
            ret = self.sock.recv(length)
        except:
            ret = ""
        self._log("Get Response: " + ret, self._loglevel)
        return ret

    def set_pause(self, pause):
        """Sets the timeout used in read socket response, e.g. "120 sec".

        The read operations will for this time before starting to read from
        the output. To run operations that take a long time to generate their
        complete output, this timeout must be set accordingly.
        """
        old = utils.secs_to_timestr(self._pause)
        self._pause = float(utils.timestr_to_secs(pause))
        return old

    def set_timeout(self, timeout):
        """Sets the timeout used in read operations to given value represented as timestr, e.g. "120 sec".

        The read operations will for this time before starting to read from
        the output. To run operations that take a long time to generate their
        complete output, this timeout must be set accordingly.
        """
        old = utils.secs_to_timestr(self._timeout)
        self._timeout = float(utils.timestr_to_secs(timeout))
        return old

    def set_loglevel(self, loglevel):
        old = self._loglevel
        self._loglevel = loglevel
        return old

    def close_connection(self, loglevel=None):
        """Closes current Telnet connection.

        Logs and returns possible output.
        """
        loglevel = loglevel is None and self._loglevel or loglevel
        telnetlib.Telnet.close(self)
        ret = self.read_all()
        self._log(ret, loglevel)
        self._log("Disconnect from %s" % str(self), "INFO")
        self._dumper.close()
        return ret

    def disconnect_LMT_BBP(self, cmd_prompt):

        logout_cmd = "lgo:;"

        self.write(logout_cmd)
        time.sleep(1)

        ret = self.read(None)
        if cmd_prompt in ret:
            print("logout LMT BBP successfully!")
        else:
            print("logout LMT BBP error!")

        return ret

    def login_LMT_BBP(self, username, password, cmd_prompt):
        ret = ''
        self.user = username
        self.password = password
        login_cmd = "lgi:op=" + "\"" + self.user + "\"" + ",pwd=" + "\"" + self.password + "\"" + ";"
        print(login_cmd)
        self.write(login_cmd)

        time.sleep(1)
        ret = self.read(None)
        if cmd_prompt in ret:
            print("login LMT BBP successfully!")
        else:
            print("login LMT BBP error!")

        return ret

    def login(self, username, password='', login_prompt='login: ',
              password_prompt='Password: '):
        """Logs in to Telnet server with given user information.

        The login keyword reads from the connection until login_prompt is
        encountered and then types the username. Then it reads until
        password_prompt is encountered and types the password. The rest of the
        output (if any) is also read and all text that has been read is
        returned as a single string.

        Prompt used in this connection can also be given as optional arguments.
        """
        self.user = username
        self.password = password
        origprompt = self.set_prompt(login_prompt)
        if six.PY2:
            ret = self.read_until_prompt(None) + username + '\n'
        else:
            ret = self.read_until_prompt(None).decode() + username + '\n'
        self.write(username)
        if password != '':
            self.set_prompt(password_prompt)
            if six.PY2:
                ret += self.read_until_prompt(None) + '*' * len(password) + '\n'
            else:
                ret += self.read_until_prompt(None).decode() + '*' * len(password) + '\n'
            self.write(password)
        self.set_prompt(origprompt)
        if self._prompt is None:
            time.sleep(1)
            ret += self.read(None)
        else:
            if ret.find("openSUSE") == -1:
                # 2019.11.05 Jufei comment the print line
                # print("not SUSE system")
                if six.PY2:
                    ret += self.read_until_prompt()
                else:
                    ret += self.read_until_prompt().decode()
            else:
                # print("SUSE system")
                ret += self.get_recv(512)
                # print(ret.find("Terminal type?"))
                self.write("vt100\n")    # add default Terminal type
                ret += self.read_until_prompt()
        return ret

    def login_catapult(self, username, password='', login_prompt='login: ',
                       password_prompt='Password: '):
        """Modified based on "login"
        """
        self.user = username
        self.password = password
        origprompt = self.set_prompt(login_prompt)
        ret = self.read_until_prompt(None) + username + '\n'
        self.write(username)
        if password != '':
            self.set_prompt(password_prompt)
            ret += self.read_until_prompt(None) + '*' * len(password) + '\n'
            self.write(password)
            ret += self.get_recv(512)
            # Check if prompt "unknown terminal tpye network"
            if ret.find("Terminal tpye?"):
                self.write("vt100\n")
        self.set_prompt(origprompt)
        if self._prompt is None:
            time.sleep(1)
            ret += self.read(None)
        else:
            ret += self.read_until_prompt()
        return ret

    def login_converter(self, username, password, input_board="3", baudrate="5", login_prompt='login: ',
                        password_prompt='Password: ', board_prompt='', baudrate_prompt=''):
        """Logs in to beamforming server with given user information.

        The login keyword reads from the connection until login_prompt is
        encountered and then types the username. Then it reads until
        password_prompt is encountered and types the password. The rest of the
        output (if any) is also read and all text that has been read is
        returned as a single string.

        Prompt used in this connection can also be given as optional arguments.
        """
        self.user = username
        self.password = password
        origprompt = self.set_prompt(login_prompt)
        ret = self.read_until_prompt(None) + username + '\n'
        self.write(username)

        self.set_prompt(password_prompt)
        ret += self.read_until_prompt(None) + '*' * len(password) + '\n'
        self.write(password)
        self.set_prompt(board_prompt)
        ret += self.read_until_prompt(None) + input_board + '\n'
        self.write(input_board)
        self.set_prompt(baudrate_prompt)
        ret += self.read_until_prompt(None) + baudrate + '\n'
        self.write(baudrate + "\r")
        self.set_prompt(origprompt)
        if self._prompt is None:
            time.sleep(1)
            ret += self.read(None)
        else:
            ret += self.read_until_prompt()
        return ret

    def write(self, text):
        """Writes given text over the connection and appends newline"""
        # self.write_bare(text + self._newline)
        self.write_bare(text)
        self.write_bare(self._newline)

    def write_for_F8(self, text):
        """Writes given text over the connection F8"""
        self.write_bare(text)

    def write_bare(self, text):
        """Writes given text over the connection without appending newline"""
        try:
            text = str(text)
        except UnicodeError:
            msg = 'Only ascii characters are allowed in telnet. Got: %s' % text
            raise ValueError(msg)
        if text != self._newline:
            sDict = {chr(3): "Ctrl-C", "\x18": "Ctrl-X", "\x19": "Ctrl-Y"}
            # print("*INFO* Execute command: " + sDict.get(text, text))
        telnetlib.Telnet.write(self, text)
        self._dumper.write("\n<--%s-->\n" % text)

    def read(self, loglevel=None):
        """Reads and returns/logs everything currently available on the output.

        Read message is always returned and logged but log level can be altered
        using optional argument. Available levels are TRACE, DEBUG, INFO and
        WARN.
        """
        loglevel = loglevel is None and self._loglevel or loglevel
        ret = self.read_very_eager()
        self._log(ret, loglevel)
        return ret

    def read_until_prompt(self, loglevel=None):
        """Reads from the current output until prompt is found.

        Expected is a list of regular expressions, and keyword returns the text
        up until and including the first match to any of the regular
        expressions.
        """
        loglevel = loglevel is None and self._loglevel or loglevel
        ret = self.expect(self._prompt, self._timeout)
        if ret[0] == -1:
            self._log("Get Response: " + ret[2], 'WARN')
            raise AssertionError("No match found for prompt '%s',detail info: %s "
                                 % (utils.seq2str([x.pattern for x in self._prompt], lastsep=' or '), ret[2]))
        self._log("Get Response: " + ret[2], loglevel)
        return ret[2]

    def set_prompt(self, *prompt):
        """Sets the prompt used in this connection to 'prompt'.

        'prompt' can also be a list of regular expressions
        """
        old_prompt = self._prompt
        if len(prompt) == 1:
            if isinstance(prompt[0], str):
                self._prompt = list(prompt)
            else:
                self._prompt = prompt[0]
        else:
            self._prompt = list(prompt)
        indices = list(range(len(self._prompt)))
        for i in indices:
            if isinstance(self._prompt[i], str):
                self._prompt[i] = re.compile(self._prompt[i], re.MULTILINE)
        return old_prompt

    def start_log_buffer(self):
        """ start copying the print outputs of _log into the log buffer """
        self._log_buffer = ""
        self._log_buffering = True

    def write_log_buffer(self, loglevel):
        """ print the log buffer with the specified loglevel and clear the buffer """
        if self._log_buffer:
            self._log_buffering = False
            self._logger.log(self._log_buffer, loglevel)
            self._log_buffer = ""
            self._log_buffering = True

    def stop_log_buffer(self):
        """ stop copying the print output of _log into the log buffer and clear the buffer """
        self._log_buffering = False
        self._log_buffer = ""

    def _log(self, msg, loglevel=None):
        self._logger.log(msg, loglevel)
#        loglevel = loglevel == None and self._loglevel or loglevel
#        msg = msg.strip()
#        if msg != '' and loglevel is not None:
#            print '*%s* %s' % (loglevel.upper(), msg)
        if self._log_buffering:
            self._log_buffer += msg

    def expect(self, in_list, timeout=None, timeout_add=True):
        self._log("Telnet: >>expect %s" % utils.get_time(), "TRACE")
        re = None
        indices = list(range(len(in_list)))
        # indices = range(len(list))
        if timeout is not None:
            _old_timeout = timeout
            from time import time
            time_start = time()
        while 1:
            self.process_rawq()
            # pos = max(0, len(self.cookedq) - 50)
            # change '50' to '256' as sometimes the length of prompt could be more than 50 characters
            pos = max(0, len(self.cookedq) - 256)
            for i in indices:
                m = in_list[i].search(self.cookedq.decode(), pos)
                if m:
                    text = self.cookedq[:m.end()]
                    self.cookedq = self.cookedq[m.end():]
        #                    print "*DEBUG* |%s| %d %d" % (m.string[m.start():m.end()], m.end(), m.endpos)
                    self._log("Telnet: <<expect %s found % s" % (utils.get_time(), in_list[i].pattern), "TRACE")
                    return (i, m, text)
            if self.eof:
                self._log("Telnet: Eof detected", "WARN")
                break
            if timeout is not None:
                elapsed = time() - time_start
                if elapsed >= timeout:
                    self._log("Telnet: Elapsed time exceeds timeout -> No further check", "WARN")
                    break
                s_args = ([self.fileno()], [], [], 5)  # timeout-elapsed)
                # self._log("Telnet: waiting select...", "Trace")
                r, w, x = select(*s_args)
                # self._log("Telnet: select end  r:%s w:%s x:%s" % (r, w, x), "Trace")
                # self._log("Telnet: timeout:%s   elapsed:%s __timeout:%s" % (timeout, elapsed, self._timeout), "Trace")

                if not r:
                    continue
                else:
                    if timeout_add is True:
                        time_start = time()
                        timeout = _old_timeout

#                if not r:
                    # self._log("Telnet: Select System call timed out", "TRACE")
                    # try:
                    #     import subprocess
                    #     self._log("expect: " + subprocess.Popen("ping -n 5 %s" % self.host, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0], "WARN")
                    # except:
                    #     import traceback
                    #     self._log("expect: " + traceback.format_exc(), "WARN")
                    # break
#                    continue
#            if timeout_add is True:
#                timeout += 5
            self.fill_rawq()
        text = self.read_very_lazy()
        if not text and self.eof:
            self._log("Telnet: <<expect %s raise eof error" % utils.get_time(), "WARN")
            raise EOFError
        self._log("Telnet: <<expect %s no any pattern matched" % utils.get_time(), "WARN")
        return (-1, None, text)

    def process_rawq(self):
        """Transfer from raw queue to cooked queue.

        Set self.eof when connection is closed.  Don't block unless in
        the midst of an IAC sequence.

        """
        buf = ['', '']
        try:
            while self.rawq:
                c = self.rawq_getchar()
                self._dumper.write(c)
                if not self.iacseq:
                    if c == telnetlib.theNULL:
                        continue
                    if c == "\021":
                        continue
                    if c != telnetlib.IAC:
                        buf[self.sb] = buf[self.sb] + c
                        continue
                    else:
                        # print(type(self.iacseq), type(c), type(to_str(c)))
                        if six.PY3:
                            self.iacseq = add_str(self.iacseq, c)
                        else:
                            self.iacseq += c
                elif len(self.iacseq) == 1:
                    # 'IAC: IAC CMD [OPTION only for WILL/WONT/DO/DONT]'
                    if c in (telnetlib.DO, telnetlib.DONT, telnetlib.WILL, telnetlib.WONT):
                        # print(type(self.iacseq), type(c))
                        if six.PY3:
                            self.iacseq = add_str(self.iacseq, c)
                        else:
                            self.iacseq += c
                        continue

                    self.iacseq = ''
                    if c == telnetlib.IAC:
                        buf[self.sb] = buf[self.sb] + c
                    else:
                        if c == telnetlib.SB:  # SB ... SE start.
                            self.sb = 1
                            self.sbdataq = ''
                        elif c == telnetlib.SE:
                            self.sb = 0
                            self.sbdataq = self.sbdataq + buf[1]
                            buf[1] = ''
                        if self.option_callback:
                            # Callback is supposed to look into
                            # the sbdataq
                            self.option_callback(self.sock, c, NOOPT)
                        else:
                            # We can't offer automatic processing of
                            # suboptions. Alas, we should not get any
                            # unless we did a WILL/DO before.
                            self.msg('IAC %d not recognized' % ord(c))
                elif len(self.iacseq) == 2:
                    cmd = self.iacseq[1]
                    self.iacseq = ''
                    opt = c
                    if opt in [telnetlib.SGA, telnetlib.ECHO]:
                        if cmd == telnetlib.DO:
                            self.sock.sendall(telnetlib.IAC + telnetlib.WILL + opt)
                        elif cmd == telnetlib.WILL:
                            self.sock.sendall(telnetlib.IAC + telnetlib.DO + opt)
                        else:
                            pass
                    elif cmd in (telnetlib.DO, telnetlib.DONT):
                        self.msg('IAC %s %d',
                                 cmd == telnetlib.DO and 'DO' or 'DONT', ord(opt))
                        if self.option_callback:
                            self.option_callback(self.sock, cmd, opt)
                        else:
                            self.sock.sendall(telnetlib.IAC + telnetlib.WONT + opt)
                    elif cmd in (telnetlib.WILL, telnetlib.WONT):
                        self.msg('IAC %s %d',
                                 cmd == telnetlib.WILL and 'WILL' or 'WONT', ord(opt))
                        if self.option_callback:
                            self.option_callback(self.sock, cmd, opt)
                        else:
                            self.sock.sendall(telnetlib.IAC + telnetlib.DONT + opt)
        except EOFError:  # raised by self.rawq_getchar()
            self.iacseq = ''  # Reset on EOF
            self.sb = 0
            pass
        i = 0
        while i < len(buf[0]):
            if buf[0][i] == chr(8):
                if i == 0:                        # BS is first element
                    buf[0] = buf[0][1:]              # remove it form buffer and the last from the queue if not LF or CR
                    if len(self.cookedq) != 0 and (self.cookedq[-1] != chr(10) and self.cookedq[-1] != chr(13)):
                        self.cookedq = self.cookedq[:-1]
                else:
                    if buf[0][i - 1] == chr(10) or buf[0][i - 1] == chr(13):
                        buf[0] = buf[0][:i] + buf[0][i + 1:]        # remove only BS from buffer
                    else:
                        buf[0] = buf[0][:i - 1] + buf[0][i + 1:]      # remove BS and previous char from buffer
                        i = i - 1
            elif buf[0][i] > chr(127):
                buf[0] = buf[0][:i] + buf[0][i + 1:]        # remove only this invalid char from buffer
            else:
                i = i + 1

        # print(type(self.cookedq), type(buf[0]))
        # self.cookedq = self.cookedq + buf[0].encode()

        if six.PY3:
            # print(type(self.cookedq), type(buf[0]), type(buf[0].encode('utf-8')))
            self.cookedq = add_str(self.cookedq, buf[0])
        else:
            self.cookedq = self.cookedq + buf[0]

        if six.PY3:
            self.sbdataq = add_str(self.sbdataq, buf[1])
        else:
            self.sbdataq = self.sbdataq + buf[1]

    def login_apc(self, username, password, login_prompt='User Name : ',
                  password_prompt='Password  :'):
        """Modified based on "login"
        """
        self.user = username
        self.password = password
        origprompt = self.set_prompt(login_prompt)
        ret = self.read_until_prompt(None) + username + '\n'
        self.write(username)
        self.set_prompt(password_prompt)
        ret += self.read_until_prompt(None) + password + '\n'
        self.write(password)
        self.set_prompt('>')
        ret += self.read_until_prompt()
        if 'RackPDU' in ret:
            apctype = 'rackpdu'
        elif 'apcE' in ret:
            apctype = 'apce'
        else:
            raise ExecutionFailed('Unkown APC type.')
        self._log('Apc type is %s' % (apctype))
        return True, apctype
