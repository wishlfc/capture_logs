from .telnet import BtsTelnet
from .ssh import SshConnection
from .ssh import CSsh
import time

BTSTELNET = BtsTelnet()

SSHCONNECTION = SshConnection()


def connect_to_ssh_host(host, port=22, user="omc", passwd="omc", prompt="", timeout="120sec"):
    """This keyword opens a SSH connection to a remote host and logs in.

    | Input Parameters | Man. | Description |
    | host      | Yes | Identifies to host |
    | port      | No  | Allows to change the default SSH port, default is 22 |
    | user      | No  | Authentication information. Default is 'omc' |
    | passwd    | No  | Authentication information. Default is 'omc' |
    | prompt    | No  | prompt as list of regular expressions. Default is: |
    |           |     | "%s@.*\$ " % user for Linux |
    | timeout   | No  | Timeout for commands issued on this connection. Default is 120 sec |

    | Return value | connection identifier to be used with 'Switch SSH Connection' |

    Example
    | Open Test | Connect to SSH Host | NetAct |
    """
    return SSHCONNECTION.connect_to_ssh_host(host, port, user, passwd, prompt, timeout)


def execute_ssh_command(command, password="", username="root", expected_return_code="0"):
    """Execute a command on the remote system. Depending on the system type some checks concerning the command success are performed.

    | Input Parameters  | Man. | Description |
    | command           | Yes  | command to be executed on the remote system |
    | password          | No   | password for user on the remote system (Linux only) |
    |                   |      | default is "", execute command as current user. |
    | username          | No   | username for execute command on the remote system (Linux only) |
    |                   |      | default is "root". |
    | expeted_return_code | No | default is '0' |

    | Return value | command output (String) |

    Example
    | Execute shell command | ${commanad} |
    """
    return SSHCONNECTION.execute_ssh_command(command, password, username, expected_return_code)


def execute_ssh_command_bare(command):
    return SSHCONNECTION.execute_ssh_command_bare(command)


def get_ssh_recv_content():
    return SSHCONNECTION.get_ssh_recv_content()


def ssh_put_file(src, des, mode='0744', newlines='LF'):
    return SSHCONNECTION.ssh_put_file(src, des, mode, newlines)


def ssh_get_file(src, des):
    return SSHCONNECTION.ssh_get_file(src, des)


def switch_ssh_connection(conn):
    """Switch to the SSH connection identified by 'conn'.
       The value of the parameter 'conn' was obtained from keyword 'Connect To SSH Host'
    """
    SSHCONNECTION.switch_ssh_connection(conn)


def disconnect_from_ssh():
    """Closes the SSH connections to the currently active remote host.
    """
    SSHCONNECTION.disconnect_from_ssh()


def disconnect_all_ssh():
    """Closes all existing SSH connections to remote hosts.
    """
    SSHCONNECTION.disconnect_all_ssh()


def set_ssh_prompt(new_prompt):
    """This keyword sets the SSH connection prompt to new prompt other than default one.
    """
    return SSHCONNECTION.set_ssh_prompt(new_prompt)


def execute_ssh_command_without_check(command, password="", username="root"):
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
    return SSHCONNECTION.execute_ssh_command_without_check(command, password, username)


def set_ssh_timeout(timeout="30sec"):
    """Allows to set a different timeout for long lasting commands.

        | Input Paramaters | Man. | Description |
        | timeout | No | Desired timeout. If this parameter is omitted, the timeout is reset to 30.0 seconds. |

        Example
        | Reset Timeout Test | Set MML Timeout |
    """
    return SSHCONNECTION.set_ssh_timeout(timeout)


def connect_to_host(host, port=23, user="", passwd="", prompt="", timeout="60sec"):
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
    | timeout   | No  | Timeout for commands issued on this connection. Default is 60 sec |

    | Return value | connection identifier to be used with 'Switch Host Connection' |

    Example
    | Open Test | Connect to Host | zeppo |
    """
    return BTSTELNET.connect_to_host(host, port, user, passwd, prompt, timeout)


def connect_to_mme(host, port=23, user="SYSTEM", passwd="SYSTEM", prompt="", timeout="120sec"):
    """This keyword opens a SSH connection to a remote host and logs in.

    | Input Parameters | Man. | Description |
    | host      | Yes | Identifies to host |
    | port      | No  | Allows to change the default SSH port, default is 23 |
    | user      | No  | Authentication information. Default is 'SYSTEM' |
    | passwd    | No  | Authentication information. Default is 'SYSTEM' |
    | prompt    | No  | prompt as list of regular expressions. Default is: |
    | timeout   | No  | Timeout for commands issued on this connection. Default is 120 sec |

    | Return value | connection identifier to be used with 'Switch SSH Connection' |

    Example
    | Open Test | Connect to MME | MME |
    """
    return BTSTELNET.connect_to_mme(host, port, user, passwd, prompt, timeout)


def get_current_connection_type():
    return BTSTELNET.get_current_connection_type()


def connect_to_rru(host, port=23, user="", passwd="", prompt="", timeout="30sec"):
    """This keyword opens a telnet connection to a rru.

    | Input Parameters | Man. | Description |
    | host      | Yes | Identifies to host |
    | port      | No  | Allows to change the default telnet port |
    | user      | No  | Authentication information. Default is '' |
    | passwd    | No  | Authentication information. Default is '' |
    | prompt    | No  | prompt as list of regular expressions. Default is: '' |
    | timeout   | No  | Timeout for commands issued on this connection. Default is 30 sec |

    | Return value | connection identifier to be used with 'Switch Host Connection' |

    Example
    | Open Test | Connect to RRU | ${RRU_IP} |
    """
    return BTSTELNET.connect_to_rru(host, port, user, passwd, prompt, timeout)


def connect_to_bts(host, port=22, user="", passwd="", prompt="", timeout="60sec"):
    """This keyword opens a telnet connection to BTS FCM unit.

    | Input Parameters | Man. | Description |
    | host      | Yes | Identifies to host |
    | port      | No  | Allows to change the default telnet port |
    | user      | No  | Authentication information. Default is '' |
    | passwd    | No  | Authentication information. Default is '' |
    | prompt    | No  | prompt as list of regular expressions. Default is: '' |
    | timeout   | No  | Timeout for commands issued on this connection. Default is 60 sec |

    | Return value | connection identifier to be used with 'Switch Host Connection' |

    Example
    | Open Test | Connect to BTS | 192.168.255.1 |
    """
    return SSHCONNECTION.connect_to_bts(host, port, user, passwd, prompt, timeout)


def send_command_to_fcmd_from_bts_control_pc(host, user, passwd, command):
    """This keyword send command to FCTB from BTS PC.

    | Input Parameters | Man. | Description                       |
    | host             | Yes  | Identifies to host                |
    | user             | Yes  | Authentication information        |
    | passwd           | Yes  | Authentication information        |
    | command          | Yes  | Command to be executed            |

    Example
    | send command to fcmd from bts control pc | 192.168.255.1  | toor4nsn | oZPS0POrRieRtu | ps |
    """
    return BTSTELNET.send_command_to_fcmd_from_bts_control_pc(host, user, passwd, command)


def login_aashell():
    """This keyword is used to login aashell
    """

    return SSHCONNECTION.login_aashell()


def exit_aashell(prompt):
    """This keyword is used to exit aashell

    | Input Parameters | Man. | Description                                  |
    | prompt           | Yes  | the prompt when exit aashell finished        |


    Example
    | exit_aashell | 'root@FSP.*:~ >' |

    """

    return SSHCONNECTION.exit_aashell(prompt)


def execute_aashell_command(command, prompt):
    """This keyword is used to execute command in aashell

    | Input Parameters | Man. | Description                                       |
    | aashell_cmd      | Yes  | the command you want to execute in aashell        |
    | cmd_prompt       | Yes  | the prompt when command execution is finished     |


    Example
    | execute_aashell_command | 'file -l 0x1231 /ram' | 'AaShell>' |

    """

    return SSHCONNECTION.execute_aashell_command(command, prompt)


def send_command_to_fsp_from_fctb(host, user, passwd, command, exit_flag='exit', timeout='120'):
    """This keyword login to FCTB, send command to FSP.

    | Input Parameters | Man. | Description                       |
    | host             | Yes  | Identifies to host                |
    | user             | Yes  | Authentication information        |
    | passwd           | Yes  | Authentication information        |
    | command          | Yes  | Command to be executed            |

    Example
    | send command to fsp from fctb | 192.168.253.18 | toor4nsn | oZPS0POrRieRtu | df -m |
    """
    return SSHCONNECTION.send_command_to_fsp_from_fctb(host, user, passwd, command, exit_flag, timeout)


def copy_file_from_fctb_to_fspc(copy_command, password):
    """This keyword login to FCTB, send command to FSP.

    | Input Parameters | Man. | Description                |
    | copy_command     | Yes  | copy command        |
    | password         | Yes  | the password of fspc |


    Example
    | Send Command To FSP From FCTB | scp /tmp/bigmem.file toor4nsn@${bts fsp}:/tmp | oZPS0POrRieRtu |

    """
    return SSHCONNECTION.copy_file_from_fctb_to_fspc(copy_command, password)


def connect_to_aashell(host, port, user="", passwd="", prompt="", timeout="10sec"):
    """This keyword opens a telnet connection to Aashell.

    | Input Parameters | Man. | Description |
    | host      | Yes | 192.168.255.1       |
    | port      | No  | 15007               |
    | user      | No  | Default is ''       |
    | passwd    | No  | Default is ''       |
    | prompt    | No  | Default is ''       |
    | timeout   | No  | Timeout for commands issued on this connection. Default is 10 sec |

    | Return value | connection identifier to be used with 'Switch Host Connection' |

    Example
    | Open Test | Connect to Aashell | 192.168.255.1 | 15007 |
    """
    return BTSTELNET.connect_to_aashell(host, port, user, passwd, prompt, timeout)


def connect_to_tm500(host, port=5003, prompt="", timeout="60sec"):
    """This keyword opens a telnet connection to TM500 with port 5003.

    | Input Parameters | Man. | Description |
    | host      | Yes | Identifies to host |
    | port      | No  | Allows to change the default telnet port |
    | prompt    | No  | prompt as list of regular expressions. Default is: '' |
    | timeout   | No  | Timeout for commands issued on this connection. Default is 60 sec |

    | Return value | connection identifier to be used with 'Switch Host Connection' |

    Example
    | Open Test | Connect to TM500 | 192.168.255.100 |
    """
    return BTSTELNET.connect_to_tm500(host, port, prompt, timeout)


def connect_to_converter(host, port=1110, user="root", passwd="admin", input_board="3", baudrate="5", prompt="", timeout="10sec"):
    """This keyword opens a telnet connection to converter with port 1110.

    | Input Parameters | Man. | Description |
    | host      | Yes | Identifies to host |
    | port      | No  | Allows to change the default telnet port |
    | prompt    | No  | prompt as list of regular expressions. Default is: '' |
    | timeout   | No  | Timeout for commands issued on this connection. Default is 60 sec |

    | Return value | connection identifier to be used with 'Switch Host Connection' |

    Example
    | Open Test | Connect to Converter | 17.21.2.15 | 1110 | root | admin | 3 | 5 |
    """
    return BTSTELNET.connect_to_converter(host, port, user, passwd, input_board, baudrate, prompt, timeout)


def connect_to_LMT_BBP(host, port=6000, user="admin", passwd="admin", cmd_prompt="RETCODE = 0  Operation succeeded.", prompt=""):
    """This keyword opens a telnet connection to LMT BBP with port 6000.

    | Input Parameters | Man. | Description |
    | host          | Yes | Identifies to host |
    | port          | No  | Allows to change the default telnet port |
    | user          | No  | user name to login to LMT BBP |
    | passwd        | No  | password to login to LMT BBP |
    | cmd_prompt    | No  | the info you want to check after sent cmd |

    | Return value | connection identifier to be used with 'Switch Host Connection' |

    Example
    | Open Test | Connect to LMT BBP | 192.168.103.13 | 6000 | admin | admin |
    """

    return BTSTELNET.connect_to_LMT_BBP(host, port=6000, user="admin", passwd="admin", cmd_prompt="RETCODE = 0  Operation succeeded.", prompt="")


def execute_cmd_LMT_BBP(cmd, cmd_prompt="RETCODE = 0  Operation succeeded."):
    """This keyword executes command in LMT BBP and return result.

    | Input Parameters | Man. | Description |
    | command              | Yes  | LMT BBP command |
    | cmd_prompt           | No   | the info you want to check after sent cmd |

    | Return value | The response from TM500 for the command being executed |

    Example
    | ${response} | Execute cmd LMT BBP | neg opt:on=cc,st=off; |
    """

    return BTSTELNET.execute_cmd_LMT_BBP(cmd, cmd_prompt="RETCODE = 0  Operation succeeded.")


def disconnect_from_LMT_BBP(cmd_prompt="RETCODE = 0  Operation succeeded."):
    """Closes existing telnet connections to LMT BBP.
    """

    return BTSTELNET.disconnect_from_LMT_BBP(cmd_prompt="RETCODE = 0  Operation succeeded.")


def connect_to_catapult(host="10.68.152.158", port=23, user="catapult", passwd="catapult", prompt="", timeout="30sec"):
    """This keyword opens a telnet connection to catapult.

        | Input Parameters | Man. | Description |
        |       host       |  No  | Default is "10.206.25.151" |
        |       port       |  No  | Allows to change the default telnet port |
        |       user       |  No  | username |
        |      passwd      |  No  | password |
        |      prompt      |  No  | prompt as list of regular expressions. Default is: |
        |      timeout     |  No  | Timeout for commands issued on this connection. Default is 30 sec |

        Example
        | Connect To Catapult | 10.68.152.158 |
    """
    return BTSTELNET.connect_to_catapult(host, port, user, passwd, prompt, timeout)


def execute_tm500_command_without_check(command, length='2048', delay_timer='0.1', exp_prompt='', newtimeout=600, ignore_output='N'):
    """This keyword executes TM500 command without any check.

    | Input Parameters | Man. | Description |
    | command          | Yes  | TM500 command |
    | length           | No   | The length of TM500 response returned, default value is 2048 bytes |

    | Return value | The response from TM500 for the command being executed |

    Example
    | ${response} | Execute TM500 Command Without Check | \#$$CONNECT |
    """
    return BTSTELNET.execute_tm500_command_without_check(command, length, delay_timer, exp_prompt, newtimeout, ignore_output)


def execute_tm500_command(command, length='2048', delay_timer='0', exp_prompt=''):
    """This keyword executes TM500 command and simply check that response should contain 'OK'.

    | Input Parameters | Man. | Description |
    | command          | Yes  | TM500 command |
    | length           | No   | The length of TM500 response checked, default value is 2048 bytes |

    Example
    | ${response} | Execute TM500 Command | \#$$START_LOGGING |
    """
    return BTSTELNET.execute_tm500_command(command, length, delay_timer, exp_prompt)


def read_tm500_output(timeout=0):
    return BTSTELNET.read_tm500_output(timeout)


def execute_tm500_file_without_check(file_dir, pause_time=None, last_command_pause_time=None):
    """This keyword executes TM500 raw file without any check.

    | Input Parameters | Man. | Description |
    | file_dir         | Yes  | TM500 raw file directory |
    | pause_time       | No   | Pause for TM500 commands except for last one |
    | last_command_pause_time | No | Pause for last TM500 command |

    Example
    | ${response} | Execute TM500 File Without Check | C:\\attach.txt |
    """
    return BTSTELNET.execute_tm500_file_without_check(file_dir, pause_time, last_command_pause_time)


def execute_shell_command_without_check(command, timeout="0", password="", username="root"):
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
    return BTSTELNET.execute_shell_command_without_check(command, timeout, password, username)


def execute_shell_command(command, password="", username="root"):
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
    return BTSTELNET.execute_shell_command(command, password, username)


def execute_shell_command_bare(command):
    """Execute a command on the remote system, without newline added, and without read the return msg.

    | Input Parameters  | Man. | Description |
    | command           | Yes  | command to be executed on the remote system |

    Example
    | Execute shell command bare | ${command} |
    """
    return BTSTELNET.execute_shell_command_bare(command)


def disconnect_all_hosts():
    """Closes all existing telnet connections to remote hosts.
    """
    BTSTELNET.disconnect_all_hosts()


def disconnect_from_host():
    """Closes the telnet connections to the currently active remote host.
    """
    BTSTELNET.disconnect_from_host()


def switch_host_connection(conn):
    """Switch to the connection identified by 'conn'.
       The value of the parameter 'conn' was obtained from keyword 'Connect to Host'
    """
    BTSTELNET.switch_host_connection(conn)


def switch_host_connection_by_ssh(conn):
    """Switch to the connection identified by 'conn'.
       The value of the parameter 'conn' was obtained from keyword 'Connect to Host'
    """
    SSHCONNECTION.switch_host_connection(conn)


def set_host_prompt(new_prompt):
    """This keyword sets the connection prompt to new prompt other than default one.

    | Input Parameters  | Man. | Description |
    | new_prompt        | Yes  | New prompt for connection |

    | Return value | original connection prompt |

    Example
    | ${old_prompt} = | Set Host Prompt | # |
    """
    return BTSTELNET.set_host_prompt(new_prompt)


def set_shell_timeout(new_timeout):
    """This keyword sets the new connection timeout.

    | Input Parameters  | Man. | Description |
    | conn              | Yes  | Connection identification |
    | new_timeout       | Yes  | New timeout for connection |

    | Return value | original connection timeout |

    Example
    | ${old_timeout} = | Set Host Timeout | 100 |
    """
    return BTSTELNET.set_shell_timeout(new_timeout)


def set_pause_time(new_pause_time):
    """This keyword sets the new connection timeout.

    | Input Parameters  | Man. | Description |
    | conn              | Yes  | Connection identification |
    | new_timeout       | Yes  | New timeout for connection |

    | Return value | original connection timeout |

    Example
    | ${old_timeout} = | Set Host Timeout | 100 |
    """
    return BTSTELNET.set_pause_time(new_pause_time)


def get_recv_content(recv_length=2048):
    """This keyword sets the new connection timeout.

    | Input Parameters  | Man. | Description |
    | get_recv_content  | Yes  | length for receive |

    Example
    | get recv content | 5000 |
    """
    return BTSTELNET.get_recv_content(recv_length)


def Check_Axis_power(RF_Mode, RF_Count=1, RF1_ip='192.168.254.129', RF2_ip='192.168.254.137', RF3_ip='192.168.254.145', username='root', password='axis', port=23):
    """This keyword sets the new connection timeout.
    | Input Parameters  | Man. | Description |
    | RF_Mode           | Yes  | Must be SISO or MIMO |
    | RF_Count          | No   | Count of RF on BTS,default is 1 |
    | RF1_ip            | No   | RF1 LAN ip,the default value is "192.168.254.129"  |
    | RF2_ip            | No   | RF2 LAN ip,the default value is "192.168.254.137"  |
    | RF3_ip            | No   | RF3 LAN ip,the default value is "192.168.254.145"  |
    | username          | No   | RF username,default is "root" |
    | password          | No   | RF password ,default is "axis" |
    | port              | No   | RF telnet port  |

    Example
    | Check_Axis_power | SISO |
    """
    BTSTELNET.Check_Axis_power(RF_Mode, RF_Count=1, RF1_ip='192.168.254.129',
                               RF2_ip='192.168.254.137',
                               RF3_ip='192.168.254.145',
                               username='root',
                               password='axis',
                               port=23)


def execute_netact_command(command, host, username, passwd, port=22, prompt="]$", timeout="10min"):
    """This keyword execute a NetAct command on the remote system
    | Input Parameters | Man. | Description                                          |
    | command          | Yes  | command to be executed on the remote system          |
    | host             | Yes  | Identifies to host                                   |
    | username         | Yes  | username for execute command on the remote system    |
    | password         | Yes  | password for user on the remote system               |
    | port             | No   | Allows to change the default SSH port, default is 22 |

    Example
    | execute_netack_command | ls | 10.56.219.6 | omc | omc |
    """
    """
    Netact = CSsh(host, port, username, passwd)
    ret = Netact.SendCmd(command)
    Netact.Disconnect()
    return ret
    """
    connect_to_ssh_host(host, port, username, passwd, prompt)
    old_timeout = set_ssh_timeout(timeout)
    ret = execute_ssh_command_without_check(command)
    set_ssh_timeout(old_timeout)
    disconnect_from_ssh()
    return ret


def connect_to_apc(host, port=23,  prompt="", timeout="30sec"):
    """This keyword opens a telnet connection to a remote host and logs in.

    | Input Parameters | Man. | Description |
    | host      | Yes | Identifies to host |
    | port      | No  | Allows to change the default telnet port |
    | prompt    | No  | prompt as list of regular expressions. Default is: |
    | timeout   | No  | Timeout for commands issued on this connection. Default is 120 sec |
    | Return value | connection identifier to be used with 'Switch Host Connection' |
    """
    return BTSTELNET.connect_to_apc(host, port=23, prompt="", timeout="30sec")


def power_reset_apc(outlet, times='60'):
    """power reset apc, times is wait time from off to on.
    """
    return BTSTELNET.power_reset_apc(outlet, times='60')

if __name__ == '__main__':

    pass
