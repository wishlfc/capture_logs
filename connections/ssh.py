"""
This library supports keywords to
   - log in to a remote Linux or Microsoft Windows host via telnet
   - execute any command supported by the underlying operting system

"""

import re
import time
import string
import paramiko
import logging

from robot.errors import ExecutionFailed
from SSHLibrary import SSHLibrary

try:
    mod = __import__("version", globals())
    __version__ = mod.version
except:
    __version__ = "0.0.0"

import sys
try:
    from SSHLibrary import __version__ as _SSHLIB_VERSION
except:
    from SSHLibrary.version import VERSION as _SSHLIB_VERSION


class MySshLib(SSHLibrary):
    def __init__(self, timeout=3, newline='LF', prompt=None):
        SSHLibrary.__init__(self, timeout, newline, prompt)
        self.type = "SSH"

    def open_connection(self, host, alias=None, port=22, timeout=None,
                        newline=None, prompt=None):
        self.host, self.port = host, port
        return SSHLibrary.open_connection(self, host, alias, port, timeout, newline, prompt)
    if _SSHLIB_VERSION == "1.1":
        @property
        def _prompt(self):
            return self.ssh_client.config.prompt

        @_prompt.setter
        def _prompt(self, new_prompt):
            old_prompt = self._prompt
            self.ssh_client.config.update(prompt=new_prompt)
            return old_prompt

        def set_timeout(self, new_timeout):
            old_timeout = self.ssh_client.config.timeout
            self.ssh_client.config.update(timeout=new_timeout)
            return old_timeout
    if _SSHLIB_VERSION == "2.1.1":
        @property
        def _prompt(self):
            return self.current.config.prompt

        @_prompt.setter
        def _prompt(self, new_prompt):
            old_prompt = self._prompt
            self.current.config.update(prompt=new_prompt)
            return old_prompt

        def set_timeout(self, new_timeout):
            old_timeout = self.current.config.timeout
            self.current.config.update(timeout=new_timeout)
            return old_timeout

    def login(self, username, password):
        self.user = username
        self.password = password
        return SSHLibrary.login(self, username, password)


class SshConnection:

    def __init__(self):
        self._ssh_connections = {}
        self._current = None
        self._loglevel = "INFO"

    def connect_to_ssh_host(self, host, port=22, user="omc", passwd="omc", prompt="", timeout="60sec"):
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
        | Open Test | Connect To SSH Host | OMS |

        Note
        When log in some device, it don't need input user name, for example ESA,
        you must input uesr by '' to replace it.
        """
        if prompt is None or prompt == "":
            myprompt = '#'
            # myprompt = None
        else:
            myprompt = prompt

        conn = MySshLib(timeout, "CR", myprompt)
        conn.open_connection(host, port=port)
        conn.login(user, passwd)

        self._ssh_connections[conn] = 'Linux'
        self._current = conn
        self._current._prompt = myprompt

        return conn

    def set_ssh_prompt(self, new_prompt):
        """This keyword sets the SSH connection prompt to new prompt other than default one.
        """
        old_prompt = self._current._prompt
        self._current._prompt = new_prompt
        # self._current.set_prompt(new_prompt)
        # print "current prompt:", repr(self._current._prompt)
        return old_prompt

    def disconnect_all_ssh(self):
        """Closes all existing SSH connections to remote hosts.
        """
        for conn in self._ssh_connections:
            conn.close_connection()
        self._ssh_connections = {}
        self._current = None

    def disconnect_from_ssh(self):
        """Closes the SSH connections to the currently active remote host.
        """
        self._ssh_connections.pop(self._current)
        self._current.close_connection()
        if len(self._ssh_connections) == 0:
            self._current = None
        else:
            self._current = list(self._ssh_connections.keys())[0]

    def switch_ssh_connection(self, conn):
        """Switch to the connection identified by 'conn'.

        The value of the parameter 'conn' was obtained from keyword 'Connect To SSH Host'
        """
        if conn in self._ssh_connections:
            self._current = conn
        else:
            raise RuntimeError("Unknow connection Switch Ssh Connection")

    def current_ssh_connection(self):
        """
        get current SSH connection.
        """
        return self._current

    def set_ssh_loglevel(self, loglevel):
        """Sets the loglevel of the current SSH connection.

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
        return self._current.set_default_log_level(loglevel)

    def set_ssh_timeout(self, timeout="30sec"):
        """Allows to set a different timeout for long lasting commands.

        | Input Paramaters | Man. | Description |
        | timeout | No | Desired timeout. If this parameter is omitted, the timeout is reset to 30.0 seconds. |

        Example
        | Reset Timeout Test | Set MML Timeout |
        """
        return self._current.set_timeout(timeout)

    def ssh_put_file(self, src, des, mode='0744', newlines='LF'):
        return self._current.put_file(src, des, mode, newlines)

    def ssh_get_file(self, src, des='.'):
        return self._current.get_file(src, des)

    def execute_ssh_command_bare(self, command):
        return self._current.write_bare(command)

    def get_ssh_recv_content(self):
        return self._current.read()

    def execute_ssh_command_without_check(self, command, password="", username="root"):
        """Execute a command on the remote system without checking the result.

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
        if self._ssh_connections[self._current] == "Linux" and password != "":
            # use "su" to change user for command execution
            self._current.write("su " + username)
            origprompt = self._current.set_prompt("Password:")
            self._current.read_until_prompt(None)
            self._current.write(password)
            self._current.set_prompt('$')
            self._current.read_until_prompt()  # if the password for 'root' is incorrect it will fail
            self._current.write(command)
            ret = self._current.read_until_regexp('\$|#')
            # get command execution result
            self._current.write('echo $?')
            raw_return_code = self._current.read_until_regexp('\$|#')
            # exit to normal user
            self._current.write('exit')
            self._current.read_until_regexp('\$|#')

        else:
            try:
                print(self._current.read())
            except:
                pass
            self._current.write(command)
        try:
            # print('commmand: [%s], current prompt:  [%s]' % (command, self._current._prompt))
            # ret = self._current.read_until_regexp(self._current._prompt)
            ret = self._current.read_until(self._current._prompt)
            # self._current.write('echo $?')
            # raw_return_code =  self._current.read_until_regexp(self._current._prompt)
            return ret
        except Exception as e:
            print(e)
            self._current.write('\x03')

    def execute_ssh_command(self, command, password="", username="root", expected_return_code="0"):
        """ Execute a command on the remote system and check the return code.
        Check the return code ($?) of the command to be the expected return code

        | Input Parameters     | Man. | Description |
        | command              | Yes  | command to be executed on the remote system |
        | expected_return_code | No   | expected return code of the command |
        |                      |      | (default is 0) |

        | Return value | command output (String) |
        """
        try:
            print(self._current.read())
        except:
            pass
        self._current.write(command)
        ret = self._current.read_until_regexp(self._current._prompt)

        # modify begin (chenjin 2012-06-25)
        # case failed for return code in lines[2] not lines[0] or lines[1]
        return_code_flag = "return code is:"
        return_code = 0
        self._current.write("echo %s$?" % return_code_flag)
        raw_return_code = self._current.read_until_regexp(self._current._prompt)

        return_lines = raw_return_code.splitlines()

        for line in return_lines:
            if line.startswith(return_code_flag):
                return_code = int(line.lstrip(return_code_flag).strip())

        if return_code != int(expected_return_code):
            raise RuntimeError("Command '%s' returned '%s' but '%s' was expected" % (command, return_code, expected_return_code))
        return ret

    def send_command_to_fsp_from_fctb(self, host, user, passwd, command, exit_flag='exit', timeout='120'):
        """This keyword will send command to FSP, you need to connect to fcmd before this step.

        | Input Parameters | Man. | Description                |
        | host             | Yes  | Identifies to host         |
        | user             | Yes  | Authentication information |
        | passwd           | Yes  | Authentication information |
        | command|         | Yes  | Command to be executed     |

        Example
        | Send Command To FSP From FCTB | 192.168.253.18 | toor4nsn | oZPS0POrRieRtu | df -m |

        """
        try:
            password_prompt = '.*assword:.*'
            old_prompt = self.set_ssh_prompt(password_prompt)
            self._current.write('ssh %s@%s' % (user, host))
            time.sleep(0.5)

            temp = self._current.read()

            if re.match('.*yes/no.*', temp.splitlines()[-1]):
                self._current.write('yes')
                self._current.read_until_regexp(password_prompt)
                self._current.write(passwd)
            elif "assword:" in temp:
                self._current.write(passwd)

            self._current.read_until_regexp('root@FSP.*:~ >')

            self.set_ssh_prompt('root@FSP.*:.*>')
            old_timeout = self.set_ssh_timeout(timeout)
            if isinstance(command, list):
                for i in range(len(command)):
                    curr_cmd = command[i]
                    if curr_cmd.startswith('prompt='):
                        self.set_ssh_prompt(curr_cmd.strip('prompt='))
                    else:
                        ret = self.execute_ssh_command_without_check(curr_cmd)
            else:
                ret = self.execute_ssh_command_without_check(command)
        finally:

            self.set_ssh_prompt(old_prompt)
            self.set_ssh_timeout(old_timeout)
            if 'exit' == exit_flag:
                self.execute_ssh_command_without_check('exit')
            return ret

    def copy_file_from_fctb_to_fspc(self, copy_command, password):
        """This keyword login to FCTB, send command to FSP.

        | Input Parameters | Man. | Description                |
        | copy_command     | Yes  | copy command        |
        | password         | Yes  | the password of fspc |


        Example
        | Send Command To FSP From FCTB | scp /tmp/bigmem.file toor4nsn@${bts fsp}:/tmp | oZPS0POrRieRtu |

        """
        common_prompt = 'yes/no.*|password:'
        try:
            old_prompt = self.set_ssh_prompt(common_prompt)

            self._current.write(copy_command)
            ret = self._current.read_until_regexp(common_prompt)
            if "yes/no" in ret:
                self._current.write('yes')
                ret = self._current.read_until_regexp(common_prompt)
            self.set_ssh_prompt(old_prompt)
            if "password:" in ret:
                self._current.write(password)
                ret = self._current.read_until_regexp(old_prompt)

        finally:
            self.set_ssh_prompt(old_prompt)

    def login_aashell(self):
        """This keyword is used to login aashell
        """
        flag = 0
        login_aashell = 'telnet 192.168.255.1 15007'
        aashell_prompt = 'AaShell>'

        self._current.write(login_aashell)
        self._current.read_until_regexp(aashell_prompt)
        flag = 1

        return flag

    def exit_aashell(self, prompt):
        """This keyword is used to exit aashell

        | Input Parameters | Man. | Description                                  |
        | prompt           | Yes  | the prompt when exit aashell finished        |


        Example
        | exit_aashell | 'root@FSP.*:~ >' |

        """

        exit_aashell = 'quit'

        self._current.write(exit_aashell)
        self._current.read_until_regexp(prompt)

    def execute_aashell_command(self, aashell_cmd, cmd_prompt='AaShell>'):

        """This keyword is used to execute command in aashell

        | Input Parameters | Man. | Description                                       |
        | aashell_cmd      | Yes  | the command you want to execute in aashell        |
        | cmd_prompt       | Yes  | the prompt when command execution is finished     |


        Example
        | execute_aashell_command | 'file -l 0x1231 /ram' | 'AaShell>' |

        """

        self._current.write(aashell_cmd)
        self._current.read_until_regexp(cmd_prompt)
        print("execute command in aashell is ok!")


class CSsh():
    """
    This is a simple class of ssh
    """
    def __init__(self, host, port=22, user='toor4nsn', passwd='oZPS0POrRieRtu'):
        self.host = host
        self.port = int(port)
        self.user = user
        self.passwd = passwd
        self.ssh = None
        self.Connect()

    def Connect(self):
        """Setup telnet connection
            Input parameters:
                n/a
            Output parameters:
                1. True if success.
                    False if failed.

        """
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.host, self.port, self.user, self.passwd)
            self.ssh = ssh

        except Exception as p_Err:
            print(p_Err)
            raise Exception("Open ssh connection error because of authentication failure or port is accopied!")

    def Disconnect(self):
        if self.ssh:
            return self.ssh.close()
        else:
            return True

    def SendCmd(self, command, RetKeyword=None):
        """Send command in ssh socket connection
            Input:
                1. Command
            Output:
                True if execute success.
                False if execute failure.
        """
        if not self.ssh:
            print("Non ssh connection, reconnect again!")
            self.connect()

        if command is None or not command:
            print("No valid command to run.")
            return True
        else:
            command = str(command)
            print("->Send: %s" % command)

        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            p_Output = stdout.readlines()
            p_Ret = string.join(p_Output)
            print("<-Receive: %s" % p_Ret)
            return p_Ret
        except:
            print("Write command failure")
            return False


if __name__ == '__main__':

    pass
