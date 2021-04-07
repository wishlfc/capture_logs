
from types import MethodType
import sys
import os
import re
import time
import datetime

from robot.errors import ExecutionFailed
from .telnet_connection import TelnetConnection

try:
    mod = __import__("version", globals())
    __version__ = mod.version
except:
    __version__ = "0.0.0"


class BtsTelnet:

    def __init__(self):
        self._telnet_connections = {}
        self._current = None
        self._loglevel = "INFO"
        self.tm500_output_file = ''
        self.apc_type = ''

    def connect_to_host(self, host, port=23, user="public", passwd="public", prompt="", timeout="120sec"):
        """This keyword opens a telnet connection to a remote host and logs in.

        | Input Parameters | Man. | Description |
        | host      | Yes | Identifies to host |
        | port      | No  | Allows to change the default telnet port |
        | user      | No  | Authentication information. Default is 'public' |
        | passwd    | No  | Authentication information. Default is 'public' |
        | prompt    | No  | prompt as list of regular expressions. Default is: |
        |           |     | "%s@.*\$ " % user for Linux |
        |           |     | "\w:.*>" for Microsoft Windows |
        |           |     | "#" for Cisco Router |
        | timeout   | No  | Timeout for commands issued on this connection. Default is 120 sec |

        | Return value | connection identifier to be used with 'Switch Host Connection' |

        Example
        | Open Test | Connect to Host | zeppo |

        Note
        When log in some device, it don't need input user name, for example ESA,
        you must input uesr by '' to replace it.
        """
        if prompt is None or prompt == "":
            myprompt = ["%s@.*[$>#]\s{0,1}" % user, "root@.*>$", "\w:.*>", ".*#"]
        else:
            myprompt = prompt

        if user != "":
            conn = TelnetConnection(host, port, myprompt, timeout, "CR")
        else:
            conn = TelnetConnection(host, port, "", timeout, "CR")

        conn.set_loglevel(self._loglevel)
        if user != "":
            ret = conn.login(user, passwd, ["login: ", "Username: ", "ENTER USERNAME <", '>'], ["password: ", "Password:\s{0,1}", "Password for .*: ", "ENTER PASSWORD <"])
        else:
            ret = conn.login(user, passwd, [""], ["password:", "Password:", "Password for .*: "])

        if ret.find("Microsoft") >= 0:
            self._telnet_connections[conn] = "Windows"
            if prompt is None or prompt == "":
                conn.set_prompt(["^[a-zA-Z]:.*>", "^.*\(y/n\)\s*", "^.*\(y/n.*\)\s*"])
        elif ret.find("[%s@" % user) >= 0:  # linux
            self._telnet_connections[conn] = "Linux"
            if prompt is None or prompt == "":
                conn.set_prompt(["%s@.*\$|\# " % user, ])
        elif ret.find("openSUSE") >= 0:
            self._telnet_connections[conn] = "Linux"
            if prompt is None or prompt == "":
                conn.set_prompt([".*#"])
        elif ret.find("Flexi Transport Module") >= 0:
            self._telnet_connections[conn] = "Linux"
            if prompt is None or prompt == "":
                conn.set_prompt([".*#"])
        else:
            self._telnet_connections[conn] = "Device"
            if prompt is None or prompt == "":
                conn.set_prompt([".*>", ".*#", "Password: "])

        self._current = conn
        return conn

    def get_current_connection_type(self):
        return self._telnet_connections[self._current]

    def connect_to_tm500(self, host, port=5003, prompt="", timeout="30sec"):
        if prompt is None or prompt == "":
            myprompt = [""]
        else:
            myprompt = prompt
        port = int(port)
        try:
            conn = TelnetConnection(host, port, myprompt, timeout, "CR")
        except:
            try:
                conn = TelnetConnection(host, port + 1, myprompt, timeout, "CR")
            except:
                conn = TelnetConnection(host, port + 2, myprompt, timeout, "CR")

        conn.set_loglevel(self._loglevel)

        self._telnet_connections[conn] = "TM500"
        if prompt is None or prompt == "":
            conn.set_prompt([""])

        self._current = conn
        return conn

    def set_host_prompt(self, new_prompt):
        """This keyword sets the connection prompt to new prompt other than default one.
        """
        old_prompt = self._current._prompt
        self._current.set_prompt(new_prompt)
        return old_prompt

    def disconnect_all_hosts(self):
        """Closes all existing telnet connections to remote hosts.
        """
        for conn in self._telnet_connections:
            conn.close_connection()
        self._telnet_connections = {}
        self._current = None

    def disconnect_from_host(self):
        """Closes the telnet connections to the currently active remote host.
        """
        self._telnet_connections.pop(self._current)
        self._current.close_connection()
        if len(self._telnet_connections) == 0:
            self._current = None
        else:
            self._current = list(self._telnet_connections.keys())[0]

    def switch_host_connection(self, conn):
        """Switch to the connection identified by 'conn'.

        The value of the parameter 'conn' was obtained from keyword 'Connect to Host'
        """
        if conn in self._telnet_connections:
            self._current = conn
            print(("Switch to '%s' now." % conn.host))
        else:
            print('switch :  ', conn)
            print('all conneciotn:  ', self._telnet_connections)
            raise RuntimeError("Unknow connection Switch Host Connection")

    def current_host_connection(self):
        """
        get current host connection.
        """
        return self._current

    def set_shell_loglevel(self, loglevel):
        """Sets the loglevel of the current host connection.

        The log level of the current connection is set. If no connection exists yet, this loglevel is used as default
        for connections created in the future. In both cases the old log level is returned, either the log level of the
        current connection or the previous default loglevel.

        | Input Paramaters | Man. | Description |
        | loglevel         | Yes  | new loglevel, e.g. "WARN", "INFO", "DEBUG", "TRACE" |

        | Return Value | Previous log level as string |
        """
        if self._current is None:
            old = self._loglevel
            self._loglevel = loglevel
            return old
        return self._current.set_loglevel(loglevel)

    def set_shell_timeout(self, timeout="30sec"):
        """Allows to set a different timeout for long lasting commands.

        | Input Paramaters | Man. | Description |
        | timeout | No | Desired timeout. If this parameter is omitted, the timeout is reset to 30.0 seconds. |

        Example
        | Reset Timeout Test | Set MML Timeout |
        """
        return self._current.set_timeout(timeout)

    def set_pause_time(self, pause="3"):
        """Allows to set a different timeout for long lasting commands.

        | Input Paramaters | Man. | Description |
        | timeout | No | Desired timeout. If this parameter is omitted, the timeout is reset to 30.0 seconds. |

        Example
        | Reset Pause Time Test | Set pause Timeout |
        """
        return self._current.set_pause(pause)

    def get_recv_content(self, length=2048):
        """Allows to set a different receive length.

        | Input Paramaters | Man. | Description |
        | timeout | No | Desired timeout. If this parameter is omitted, the length is reset to 2048. |

        Example
        | get recv content | content length |
        """
        length = int(length)
        return self._current.get_recv(length)

    def execute_shell_command(self, command, password="", username="root", timeout="0"):
        """Execute a command on the remote system. Depending on the system type some checks concerning the command success are performed.

        | Input Parameters  | Man. | Description |
        | command           | Yes  | command to be executed on the remote system |
        | password          | No   | password for user on the remote system (Linux only) |
        |                   |      | default is "", execute command as current user. |
        | username          | No   | username for execute command on the remote system (Linux only) |
        |                   |      | default is "root". |

        | Return value | command output (String) |

        Example
        | Execute shell command | ${command} |                  | # execute command as current user. |
        | Execute shell command | ${command} | ${root password} | # execute command as root. |
        """
        result = self.execute_shell_command_without_check(command, timeout, password, username)
        current_env = self._telnet_connections[self._current]
        if "Cisco" == current_env:
            if (result.lower().find("unknown command") >= 0 or
               result.lower().find("incomplete command") >= 0 or
               result.lower().find("invalid input") >= 0 or
               result.lower().find("command rejected") >= 0):
                raise Exception("Execute failed !")
        elif "Linux" == current_env:
            raw_return_code = self.execute_shell_command_without_check('echo $?')
            return_lines = raw_return_code.splitlines()
            try:
                return_code = int(return_lines[0])
            except ValueError:
                return_code = int(return_lines[1])
            if return_code != 0:
                raise Exception("Execute failed with return code: %d" % return_code)
        elif "Windows" == current_env or "MS" == current_env:
            raw_return_code = self.execute_shell_command_without_check('echo %ERRORLEVEL%')
            return_lines = raw_return_code.splitlines()
            try:
                return_code = int(return_lines[1])
            except ValueError:
                return_code = int(return_lines[0])
            if return_code != 0:
                raise Exception("Execute failed with return code: %d" % return_code)
        else:
            pass
        return result

    def execute_shell_command_without_check(self, command, timeout="0", password="", username="root"):
        """Execute a command on the remote system without checking the result.

        | Input Parameters  | Man. | Description |
        | command           | Yes  | command to be executed on the remote system |
        | timeout           | No   |  sleep time if need to set command timeout |
        | password          | No   | password for user on the remote system (Linux only) |
        |                   |      | default is "", execute command as current user. |
        | username          | No   | username for execute command on the remote system (Linux only) |
        |                   |      | default is "root". |

        | Return value | command output (String) |

        Example
        | Execute shell command | ${command} |                  | # execute command as current user. |
        | Execute shell command | ${command} | ${root password} | # execute command as root. |
        """
        if self._telnet_connections[self._current] == "Linux" and password != "" and username != "root":
            # use "su" to change user for command
            self._current.write("su " + username)
            origprompt = self._current.set_prompt("Password:")
            self._current.read_until_prompt(None)
            self._current.write(password)
            origprompt.append("%s@.*[\$|\#] " % username)
            self._current.set_prompt(origprompt)
            self._current.read_until_prompt()
            self._current.write('echo $?')
            return_lines = self._current.read_until_prompt().splitlines()
            try:
                return_code = int(return_lines[0])
            except ValueError:
                return_code = int(return_lines[1])
            if return_code != 0:
                raise Exception('CANNOT to change user %s with password:%s.' % (username, password))

        self._current.write(command)
        try:
            ret = self._current.read_until_prompt()
            time.sleep(0.25)
            tmp = self._current.read()
            return ret + tmp
        except AssertionError as e:
            print(e)
            time.sleep(float(timeout))
            self._current.write('\x13')
        self._current.write('\x03')
        time.sleep(0.25)
        self._current.write('\x03')
        raise Exception("command '%s' execution failed:'%s'" % (command, e))

    def execute_shell_command_bare(self, command):
        return self._current.write_bare(command)

    def save_tm500_log(self, output):
        if self.tm500_output_file:
            now = datetime.datetime.now()
            with open(self.tm500_output_file, 'a') as f:
                for line in output.splitlines():
                    if line.strip():
                        f.write('%s  %-100s\n' % (now.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], line.replace('\n', '')))
        else:
            self._current._log("No TM500 output file name")

    def execute_tm500_command_without_check(self, command, length='2048', delay_timer='0',
                                            exp_prompt='', newtimeout=200, ignore_output='N'):
        # read the socket queue before any command execution
        self.read_tm500_output()

        self._current.write(command)
        str1 = 'C: %s' % (command.split(' ')[0]).upper()
        str2 = 'C: %s' % (command.split(' ')[0].replace('#$$', '')).upper()

        st = time.time()
        ret = self._current.read_eager()
        self.save_tm500_log(command + '\n' + ret)
        while (True):
            buf = self._current.read_very_eager()
            if buf:
                ret += buf
                self.save_tm500_log(buf)
            if 'OK' in ret.upper():
                break
            if 'FAILURE' in ret.upper():
                break
            if str1 in ret.upper():
                break
            if str2 in ret.upper():
                break
            if time.time() - st > newtimeout:
                self._current._log("Command [%s] Timeout [%d]seconds! " % (command, newtimeout), self._loglevel)
                ret += 'TMA NO RESPONSE'
                return ret.upper()
                break
            time.sleep(0.01)

        delay_timeout = float(delay_timer)
        if delay_timeout > 0 or exp_prompt:
            st = time.time()
            while (True):
                buf = self._current.read_very_eager()
                if buf:
                    self.save_tm500_log(buf)
                    ret += buf
                    if exp_prompt.strip():
                        if exp_prompt in ret:
                            self._current._log("Found Prompt: " + exp_prompt, self._loglevel)
                            break
                if delay_timeout > 0 and time.time() - st > delay_timeout:
                    break
                time.sleep(0.01)

        if ignore_output.strip() != 'Y':
            self._current._log("Get Response: " + ret, self._loglevel)
        return ret.upper()

    def read_tm500_output(self, timeout=0):
        delay_timeout = float(timeout)
        if delay_timeout > 0:
            output = ''
            st = time.time()
            while (True):
                buf = self._current.read_very_eager()
                if buf:
                    self.save_tm500_log(buf)
                    output += buf
                if time.time() - st > delay_timeout:
                    break
                time.sleep(0.01)
        else:
            output = self._current.read_very_eager()
            self.save_tm500_log(output)
        return output

    def execute_tm500_command(self, command, length='2048', delay_timer='0', exp_prompt=''):
        ret = self.execute_tm500_command_without_check(command, length, delay_timer, exp_prompt)
        if ret.find('OK') < 0:
            raise ExecutionFailed("command '%s' execution failed" % command)
        return ret

    def execute_tm500_file_without_check(self, file_dir, pause_time=None, last_command_pause_time=None):
        try:
            file_handle = file('%s' % file_dir, 'r')
        except:
            raise ExecutionFailed("open file '%s' failed" % file_dir)
        lines = file_handle.readlines()
        # set the pause time for every TM500 commands except for last one
        my_pause_time = pause_time is None and '2' or pause_time
        old_PauseTime = self.set_pause_time(my_pause_time)

        lines = [line for line in lines if not re.match('(^(\r|\n|\s+)$)|(^$)|^#', line)]  # remove all the unnecessary lines including comment
        last_command_index = len(lines) - 1

        try:
            ret = ''
            index = 0
            for command in lines:
                if index == last_command_index:
                    my_last_pause_time = last_command_pause_time is None and '30' or last_command_pause_time
                    self.set_pause_time(my_last_pause_time)
                    ret = self.execute_tm500_command_without_check(command, '15000', '3')
                    if ret.upper().find('OK') < 0:
                        print(("command '%s' execution failed" % command))
                else:
                    if not re.match('(^(\r|\n|\s+)$)|(^$)', command):
                        ret = self.execute_tm500_command_without_check(command)
                        if ret.upper().find('OK') < 0:
                            print(("command '%s' execution failed" % command))
                index += 1
            return ret
        finally:
            self.set_pause_time(old_PauseTime)

    def execute_f8_command_without_check(self, command, length='2048'):
        self._current.write_for_F8(command)
        ret = self._current.get_recv(int(length))
        return ret.upper()

    def execute_f8_command(self, command, length='2048'):
        ret = self.execute_f8_command_without_check(command, length)
        if ret.find('OK') < 0:
            raise ExecutionFailed("command '%s' execution failed" % command)

    def execute_bash_command(self, command, expected_return_code="0"):
        """ Execute a command on the remote system and check the return code.
        Check the return code ($?) of the command to be the expected return code

        | Input Parameters     | Man. | Description |
        | command              | Yes  | command to be executed on the remote system |
        | expected_return_code | No   | expected return code of the command |
        |                      |      | (default is 0) |

        | Return value | command output (String) |
        """

        return_value = self.execute_shell_command_without_check(command)
        raw_return_code = self.execute_shell_command_without_check('echo $?')
        return_lines = raw_return_code.splitlines()
        try:
            return_code = int(return_lines[0])
        except ValueError:
            return_code = int(return_lines[1])
        if return_code != int(expected_return_code):
            raise RuntimeError("Command '%s' returned '%s' but '%s' was expected" % (command, return_code, expected_return_code))
        return return_value

    def execute_shell_command_file(self, filename, ignore_errors="NO"):
        """Executes all commands in the file identified by 'filename'

        Each line in the file is passed to 'execute_mml' or 'execute_mml_without_check'
        when this keyword is used with 'ignore_errors' set to 'YES'. Leading and trailing whitespaces are
        removed. '#' at the beginning of a line marks a comment.
        When a line starts with 'NC', the following command (seperated by a space) is executed without result checking.
        The file is first searched for in the current directory and then in the python path.

        | Input Paramaters | Man. | Description |
        | filnname         | Yes  | filenname of the file which contains the single commands |
        | ignore_errors    | No   | steers the behaviour in case of erros. Default is to check for errors |
        """
        pathlist = sys.path[:]
        pathlist.insert(0, '.')
        for path in pathlist:
            name = os.path.join(path, filename)
            if os.path.isfile(name):
                break
            name = None
        if name is None:
            raise RuntimeError("File '%s' not available in python path" % filename)
        file = open(name, mode="rb")
        res = file.read()
        file.close()
        lines = res.splitlines()
        res = ""
        for line in lines:
            line = line.strip()
            if len(line) == 0 or line.startswith("#"):
                continue
            try:
                if line.startswith("NC "):
                    res += self.execute_shell_command_without_check(line[3:])
                else:
                    res += self.execute_shell_command(line)
            except Exception as e:
                if ignore_errors == "NO" or ignore_errors == "" or ignore_errors is None:
                    raise
                else:
                    print(("*WARN* %s" % e.message))
        return res

    def ping_system(self, host_or_ip, count="1", packet_size="32", intervall="1", fromip=""):
        """'Ping System' allows to send 'count' ICMP ECHO REQUEST of size 'packet_size'
        to the host identified by 'host_or_ip'.
        OS Cisco:Ping
        OS MS:ping
        OS Linux:ping
        | Input Parameters  | Man. | Description |
        | host_or_ip        | Yes  | Name or ip address of the host which shall be pinged |
        | count             | No   | Number of echo requests. Default is 1 |
        | packet_size       | No   | Size of the echo requests. Default is 32 |
        | intervall         | No   | Time between two echo requests. Default is 1 sec. Intervals smaller than 0.2 sec are currently not supported. |
        | fromip            | No   | Ip address from where shall be pinged (-I) |

        | Return value      | Number of received ICMP ECHO RESPONSEs ("1" or "0") |

        Example
        | Ping Test | ${recv_pkg}=      | Ping System | 10.50.16.11   |
        |           | Fail unless equal | 5           | ${recv_pkg}   |
        """
        if not count or count.lower() == 'none':
            count = "1"
        if not packet_size or count.lower() == 'none':
            packet_size = "32"
        if not intervall or intervall.lower() == 'none':
            intervall = "1"

        if self._telnet_connections[self._current] == "MS":
            res = self.execute_shell_command_without_check("ping -n %s -l %s %s" % (count, packet_size, host_or_ip))
        elif self._telnet_connections[self._current] == "Cisco":
            command = "ping ip %s repeat %s size %s timeout %s" % (host_or_ip, count, packet_size, intervall)
            if fromip:
                command += " source %s" % (fromip)
            res = self.execute_shell_command_without_check(command)
        else:
            if fromip == "":
                res = self.execute_shell_command_without_check("ping -c %s -s %s -i %s %s" % (count, packet_size, intervall, host_or_ip))
            else:
                res = self.execute_shell_command_without_check("ping -c %s -s %s -i %s -I %s %s" % (count, packet_size, intervall, fromip, host_or_ip))

        if self._telnet_connections[self._current] == "Cisco":
            for line in res.splitlines():
                if line.find("Success") >= 0:
                    print(line)
                    res = line.split()[5]
                    print(res)
                    return res.split('/')[0][1:]
        else:
            for line in res.splitlines():
                if line.find("Packets:") >= 0:
                    return line.split()[6]
                if line.find("packets") >= 0:
                    return line.split()[3]
        return "0"

    def connect_to_apc(self, host, port=23,  prompt="", timeout="30sec"):
        """This keyword opens a telnet connection to a remote host and logs in.

        | Input Parameters | Man. | Description |
        | host      | Yes | Identifies to host |
        | port      | No  | Allows to change the default telnet port |
        | prompt    | No  | prompt as list of regular expressions. Default is: |
        | timeout   | No  | Timeout for commands issued on this connection. Default is 120 sec |
        | Return value | connection identifier to be used with 'Switch Host Connection' |
        """
        conn = TelnetConnection(host, port, '', timeout, "CR")
        conn.set_loglevel(self._loglevel)
        for i in range(60):
            user = 'apc'
            passwd = 'apc'
            ret, apctype = conn.login_apc(user, passwd)
            if ret:
                break
            else:
                print("APC login fail!")
                user = "apc\r"
                passwd = "apc\r"
                ret = conn.login_apc(user, passwd)
        self._telnet_connections[conn] = "APC"
        if prompt is None or prompt == "":
            conn.set_prompt([">"])
        self._current = conn
        self.apc_type = apctype
        return conn

    def send_apc_commands(self, cmdlist, prompt):
        ret = ''
        for cmd in cmdlist:
            self._current.write(cmd)
            self._current.set_prompt(prompt)
            ret += self._current.read_until_prompt()
        return ret

    def power_reset_apc(self, outlet, times='60'):
        output = ''
        prompt = '<ENTER>- Refresh, <CTRL-L>- Event Log'
        prompt_do = "Enter 'YES' to continue or <ENTER> to cancel"
        if self.apc_type.lower() == 'rackpdu':
            output += self.send_apc_commands([chr(27) * 8], prompt)
            output += self.send_apc_commands(['1', '2', '1', outlet, '1'], prompt)
            output += self.send_apc_commands(['2'], prompt_do)
            output += self.send_apc_commands(['YES'], 'Press <ENTER> to continue...')
            output += self.send_apc_commands([''], prompt)
            time.sleep(int(times))
            output += self.send_apc_commands(['1'], prompt_do)
            output += self.send_apc_commands(['YES'], 'Press <ENTER> to continue...')
            output += self.send_apc_commands([''], prompt)
        else:
            output += self.send_apc_commands(['OlOff %s' % (outlet)], 'Success')
            time.sleep(int(times))
            output += self.send_apc_commands(['OlOn %s' % (outlet)], 'Success')
        return output

if __name__ == '__main__':
    pass
