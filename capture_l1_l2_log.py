import os
import sys
import time
import subprocess
import logging

import connections

def execute_local_command(cmd='', ignore_error=True):
    print('Execute Local Command: [{}]'.format(cmd))
    stderr = open(os.devnull, 'w') if ignore_error else subprocess.PIPE
    p = subprocess.Popen(cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True)
    out, error = p.communicate()
    return out, error

class c_bts_log_s1(object):

    def __init__(self, bts_ip=None):
        self.bts_ip = bts_ip
        self.conn = None
        self.last_command_time = time.time()
        logging.getLogger('chardet.charsetprober').setLevel(logging.INFO)
        self.logger = logging.getLogger('capture_data')
        logging.basicConfig(
            format='%(asctime)s,%(msecs)d [CAPTURE_%(levelname)s] %(message)s',
            datefmt='%H:%M:%S',
            level='DEBUG')
        self.logger.setLevel('DEBUG')

    def is_reachable(self):
        for i in range(20):
            if os.system('ping -c 1 -W 5 {} >/dev/null'.format(self.bts_ip)) == 0:
                return True
            else:
                time.sleep(1)
        return False

    def get_prompt(self):
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        result = '>'
        try:
            client.connect(self.bts_ip, 22, 'toor4nsn',
                           'oZPS0POrRieRtu')
            channel = client.invoke_shell()
            while not channel.recv_ready():
                time.sleep(1)
            results = channel.recv(2048)
        finally:
            client.close()
        prompt = results.strip()[-1]
        if prompt not in ['#', ' >']:
            prompt = result
        self.logger.info('I get prompt [{}]'.format(prompt))
        return prompt

    def connect(self):
        if self.conn:
            if self.is_reachable():
                connections.switch_ssh_connection(self.conn)
            else:
                self.disconnect()
                raise Exception('S1 Interface is not reachable.')
        else:
            if self.is_reachable():
                prompt = self.get_prompt()
                self.conn = connections.connect_to_ssh_host(
                    self.bts_ip,
                    '22',
                    'toor4nsn',
                    'oZPS0POrRieRtu',
                    prompt)
                connections.switch_ssh_connection(self.conn)
            else:
                raise Exception('S1 Interface is not reachable.')
        self.last_command_time = time.time()

    def disconnect(self):
        if self.conn:
            connections.switch_ssh_connection(self.conn)
            connections.disconnect_from_ssh()
            self.conn = None

    def setup(self):
        print('Setup for S1 Interface of BTS IP: {}'.format(self.bts_ip))
        self.clear_hostkey()
        self.connect()

    def teardown(self):
        print('Teardown for S1 Interface of BTS IP: {}'.format(self.bts_ip))
        self.disconnect()

    def re_connect(self):
        try:
            if self.conn:
                connections.switch_ssh_connection(self.conn)
            connections.execute_ssh_command_without_check('ls' + '\n')
        except Exception as E:
            if 'socket' in str(E).lower():
                self.disconnect()
                self.connect()

        if time.time() - self.last_command_time > 5 * 60:
            self.logger.info('S1 link has been idle more than 5 minutes, need re-connect')
            self.disconnect()
        self.connect()
        self.last_command_time = time.time()

    def exec_command(self, command):
        self.re_connect()
        self.logger.info('Execute Command on S1: {}, prompt: [{}]'.format(
            command.replace('\n', ''), str(self.conn._prompt)))
        return connections.execute_ssh_command_without_check(command + '\n')

    def exec_command_bare(self, command):
        self.logger.info('Execute bare Command on S1: [%s]' % (command.replace('\n', '')))
        # self.re_connect()
        connections.execute_ssh_command_bare(command)

    def exec_command_on_fsp(self, command='', delay=0):
        flag = True
        self.logger.info('Execute command on FSP: [%s]' % (command.replace('\n', '')))
        self.exec_command_bare(command + '\n')
        time.sleep(1)
        output = connections.get_ssh_recv_content()
        self.logger.info('FSP output 1: [%s]' % (output))
        if 'Are you sure you want to continue connecting' in output:
            output += self.exec_command_bare('yes\n')
            time.sleep(1)
            flag = False
        if 'Password:' in output:
            self.exec_command_bare('oZPS0POrRieRtu\n')
            time.sleep(1)
            flag = False
        if delay:
            time.sleep(delay)
        if flag == False:
            output = connections.get_ssh_recv_content()
            self.logger.info('FSP output 2 : [%s]' % (output))
        return output

    def download_file(self, src_dire='', dst_dire=''):
        cmd = ('sshpass -p "oZPS0POrRieRtu" scp -o "StrictHostKeyChecking no" '
               ' -r "toor4nsn"@{bts_ip}:{src_dire} {dst_dire} 2>/dev/null').format(
            bts_ip=self.bts_ip, src_dire=src_dire, dst_dire=dst_dire)
        self.logger.info('Download BTS file: [%s] ' % (cmd))
        os.system(cmd)
    
    def upload_file(self, src_dire='', dst_dire=''):
        cmd = ('sshpass -p oZPS0POrRieRtu scp -o "StrictHostKeyChecking no" '
               ' -r {src_dire} "toor4nsn"@{bts_ip}:{dst_dire} 2>/dev/null').format(
            bts_ip=self.bts_ip, src_dire=src_dire, dst_dire=dst_dire)
        self.logger.info('Upload BTS file: [%s] ' % (cmd))
        os.system(cmd)

    def read_output(self):
        return connections.get_ssh_recv_content()

    def execut_command_local(self, command='', keyword=''):
        tcmd = ('sshpass -p "oZPS0POrRieRtu" ssh "toor4nsn"@{bts_ip} '
                ' -o StrictHostKeyChecking=no  "{command}" ').format(
            bts_ip=self.bts_ip, command=command)
        self.logger.info(tcmd)

        out, error = execute_local_command(tcmd, False)
        if out:
            self.logger.info('command output: [%s]' % (out))
        if error:
            lines = [line for line in error.splitlines() if 'Permanently' not in line and
                     'access a private system' not in line]
            if lines:
                self.logger.info('\n'.join(lines))

        if keyword.strip():
            for i in range(5):
                if keyword.upper() in out.upper():
                    break
                print('Retry for: ', i + 1)
                out, error = execute_local_command(tcmd, False)
        output = [x.replace('\n', '') for x in out.splitlines()]
        return output

    def clear_hostkey(self):
        self.logger.info('Clear Host Key for S1.')
        self.logger.info('clean /root/.ssh/known_hosts file first.')
        filename = '/root/.ssh/known_hosts'
        cmd = r"sudo sed -i '/{}/d' {}".format(self.bts_ip, filename)
        os.system(cmd)
        self.logger.info('Re-generate host key.')
        cmd = 'ssh-keygen -R [{}]:{}'.format(self.bts_ip, '22')
        return execute_local_command(cmd)

    def adjust_left_right_rack(self):
        output = self.exec_command('ownnid')
        if '0x1' in output:
            self.sack = 'left'
        elif '0x2' in output:
            self.sack = 'right'
        else:
            self.sack = ''
        return self.sack 

    def get_local_ip(self):
        self.adjust_left_right_rack()
        if self.sack == 'left':
            self.local_ip = '192.168.253.16'
        elif self.sack == 'right':
            self.local_ip = '192.168.253.32'
        else:
            self.local_ip = ''
        return self.local_ip

    def capture_runtime(self, starttime='1 min ago', endtime='now'):
        # starttime: 1 min ago or "2020-06-19 10:27:00"
        # endtime : now or "2020-06-19 10:28:00"
        self.logger.info('=========Start capture Journal on S1==========!')
        self.exec_command('rm -rf /tmp/runtime.log')
        cmd = 'journalctl --since "{}" --until "{}" -o json-pretty > /tmp/runtime.log'.format(
            starttime, endtime)
        self.exec_command(cmd)
        cmd = 'du -s {}'.format('/tmp/runtime.log')
        output = self.exec_command(cmd)
        if output.split()[0].strip() == '0':
            self.logger.warning('Capture runtime log fail!')

    def download_runtime(self, runtime_file):
        if os.path.exists(runtime_file):
            os.system('rm -r {}'.format(runtime_file))
        self.download_file('/tmp/runtime.log', runtime_file)
        if os.path.exists(runtime_file):
            self.logger.info('Download runtime log OK, file name is {}'.format(runtime_file))
        else:
            self.logger.warning('Download runtime log fail!')

    def login_asp(self, domain_slot):
        cmd = 'bsh {}'.format(domain_slot)        
        output = self.exec_command_on_fsp(cmd)
        if 'asp-' in output:
            self.logger.info('login asp success!')
        else:
            raise Exception('login asp failed!')

    def exit_asp(self):
        cmd = 'exit'
        output = self.exec_command_on_fsp(cmd)
        if 'logout' in output:
            self.logger.info('logout asp success!')
        else:
            raise Exception('logout asp failed!')
 
    def download_l2_header_log(self, l2_file):
        if os.path.exists(l2_file):
            os.system('rm -r {}'.format(l2_file))
        self.download_file('/tmp/capture.bin', l2_file)
        if os.path.exists(l2_file):
            self.logger.info('Download L2 header log OK, file name is {}'.format(l2_file))
        else:
            self.logger.warning('Download L2 header log fail!')

    def capture_l2_header_log(self, btss1ip, domain_slot, log_duration):
        self.logger.info('=========Start capture l2 header on S1==========!')
        self.login_asp(domain_slot)
        cmd = 'ls -l /proc/device-tree/reserved-memory/'
        output = self.exec_command_on_fsp(cmd)
        addr_base = ''
        for line in output.split('\n'):
            if  'region@' in line:
                addr_base = line.split('region@')[1].strip()
        if addr_base == '':
            raise Exception('Cannnot find region base addr.')
        cmd = 'devmem 0xdf400580 32 {}'.format(addr_base)
        self.logger.info(self.exec_command_on_fsp(cmd))
        cmd = 'devmem 0xdf400584 32 1048576'
        self.logger.info(self.exec_command_on_fsp(cmd))
        cmd = 'devmem 0xdf400588 32 1'
        time.sleep(int(log_duration))
        self.logger.info(self.exec_command_on_fsp(cmd))
        cmd = 'devmem 0xdf400588 32 0'
        self.logger.info(self.exec_command_on_fsp(cmd))
        cmd = 'memdump {} --count 0x100000 --file capture.bin'.format(addr_base)
        self.logger.info(self.exec_command_on_fsp(cmd))
        cmd = 'ls -lrtha'
        output = (self.exec_command_on_fsp(cmd))
        if 'capture.bin' in output:
            self.logger.info('Capture L2 header log OK!')    
        cmd = 'scp capture.bin toor4nsn@{}:/tmp'.format(self.local_ip)
        self.logger.info(self.exec_command_on_fsp(cmd))
        self.exit_asp()
        cmd = 'ls /tmp'
        output = self.exec_command(cmd)
        if 'capture.bin' in output:
            self.logger.info('Copy L2 header log OK!')

    def capture_download_l2_header_log(self, btss1ip, domain_slot, l2_file, l2_log_duration):
        self.capture_l2_header_log(btss1ip, domain_slot, l2_log_duration)
        self.download_l2_header_log(l2_file)

    def get_leka_file(self, release):
        if release in ['21A', '20B']:
            file = 'leka_tx_l1reg_list_20B.txt'
        elif release in ['20A']:
            file = 'leka_tx_l1reg_list_20A.txt'
        elif release in ['19A', '19B']:
            file = 'leka_tx_l1reg_list_R51_v01.txt'
        elif release in ['5G19']:
            file = 'registre50reduit.txt'
        else:
            file = ''
        return file

    def upload_leka_tx_file_to_fct(self, dump_file, leka_file):
        src_dump_file = '/home/work/tacase_dev/Resource/config/case/' + dump_file
        src_leka_file = '/home/work/tacase_dev/Resource/config/case/' + leka_file
        dst_dump_file = '/tmp/' + dump_file
        dst_leka_file = '/tmp/' + leka_file
        self.upload_file(src_dump_file, dst_dump_file)
        self.upload_file(src_leka_file, dst_leka_file)

    def copy_upload_leka_tx_file_to_fsp(self, dump_file, leka_file):
        cmd = 'scp toor4nsn@{}:/tmp/{} ./'.format(self.local_ip, leka_file)
        self.logger.info(self.exec_command_on_fsp(cmd))
        cmd = 'scp toor4nsn@{}:/tmp/{} ./'.format(self.local_ip, dump_file)
        self.logger.info(self.exec_command_on_fsp(cmd))

    def capture_l1_registers_of_leka_tx_dump(self, domain_slot, release, log_duration):
        dump_file = 'tx_register_dump.sh'
        leka_file = self.get_leka_file(release)
        self.logger.info('====Start capture l1 registers of leka tx dump on s1=====!')
        self.logger.info('dump_file is {}'.format(dump_file))
        self.logger.info('leka_file is {}'.format(leka_file))
        self.upload_leka_tx_file_to_fct(dump_file, leka_file)
        self.login_asp(domain_slot)
        self.copy_upload_leka_tx_file_to_fsp(dump_file, leka_file)
        cmd = 'chmod +x *.sh'
        self.logger.info(self.exec_command_on_fsp(cmd))
        cmd = 'rm test.log'
        self.logger.info(self.exec_command_on_fsp(cmd))
        cmd = './{} {} test &'.format(dump_file, leka_file)
        self.logger.info(self.exec_command_on_fsp(cmd))   
        time.sleep(int(log_duration)) 
        cmd = 'ps -ef|grep {}'.format(leka_file)
        output = self.exec_command_on_fsp(cmd)
        self.logger.info(output)
        for i in output.split('\n'):
            if dump_file in i and leka_file in i:
                jobid = i.split()[1].strip() 
                cmd = 'kill -9 {}'.format(jobid)
                self.logger.info(self.exec_command_on_fsp(cmd))    
        cmd = 'scp ./test.log  toor4nsn@{}:/tmp'.format(self.local_ip) 
        self.logger.info(self.exec_command_on_fsp(cmd)) 
        pass

    def download_l1_registers_log(self, l1_registers_file):
        if os.path.exists(l1_registers_file):
            os.system('rm -r {}'.format(l1_registers_file))
        self.download_file('/tmp/test.log', l1_registers_file)
        if os.path.exists(l1_registers_file):
            self.logger.info('Download l1 registers log OK, file name is {}'.format(l1_registers_file))
        else:
            self.logger.info('Download l1 registers log fail!')

def capture_all_log(btss1ip, domain_slot, capture_file, release, l2_file, l2_log_duration, l1_registers_file, l1_registers_log_duration, runtime_file, runtime_starttime, runtime_endtime):
    s1 = c_bts_log_s1(btss1ip)
    s1.setup()
    s1.get_local_ip()
    if s1.local_ip == "":
        raise Exception('Cannnot find local ip.')
    s1.capture_l2_header_log(btss1ip, domain_slot, l2_log_duration)
    s1.download_l2_header_log(l2_file)
    time.sleep(1)
    s1.capture_runtime(starttime=runtime_starttime, endtime=runtime_endtime)
    s1.download_runtime(runtime_file)
    s1.capture_l1_registers_of_leka_tx_dump(domain_slot, release, l1_registers_log_duration)
    s1.download_l1_registers_log(l1_registers_file)
    s1.teardown()
    print('Download all log link is {}'.format(capture_file))

if __name__ == '__main__':
    # bts_s1ip = '10.108.231.168'
    # domain_slot = '1:2'
    # log_duration = '30'
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-b",  dest="bts_s1ip", default='',
                      help='bts s1 ip, such as 10.69.xx.xx')
    parser.add_option("-d",  dest="domain_slot", default='',
                      help='domain:slot, such as 1:2')
    parser.add_option("-c",  dest="capture_file", default='',
                      help='log filename, such as "/home/work/temp/capture/"')
    parser.add_option("-r",  dest="release", default='',
                      help='release, such as 19A 19B 20A 20B 21A 5G19')    
    parser.add_option("-l",  dest="l2_log_duration", default='',
                      help='log duration, such as 30(unit is s)')
    parser.add_option("-t",  dest="l1_registers_log_duration", default='',
                      help='log duration, such as 60(unit is s)')
    parser.add_option("-m",  dest="runtime_starttime", default='',
                      help='runtime log starttime: 1 min ago or "2020-06-19 10:27:00", default is 1 min ago')
    parser.add_option("-n",  dest="runtime_endtime", default='',
                      help='runtime log endtime : now or "2020-06-19 10:28:00", default is now')
    (options, sys.argv[1:]) = parser.parse_args()

    bts_s1ip = options.bts_s1ip
    domain_slot = options.domain_slot
    l2_log_duration = options.l2_log_duration
    l1_registers_log_duration = options.l1_registers_log_duration
    capture_file = options.capture_file
    release = options.release.upper()
    runtime_starttime = options.runtime_starttime
    runtime_endtime = options.runtime_endtime
    if bts_s1ip == "":
        raise Exception('Please input bts s1 ip.') 
    else:
        print('BTS S1 IP is {}!'.format(bts_s1ip))
    if domain_slot == "":
        raise Exception('Please input domain id and slot id.') 
    else:
        print('Domain id:slot id is {}!'.format(domain_slot))
    if capture_file == "":
        timestamp = str(time.time()).split('.')[0]
        # capture_file='/home/work/temp/capture/' + timestamp + '/'
        capture_file=os.getcwd() + '/' + timestamp + '/'
        if not os.path.exists(capture_file):
            os.mkdir(capture_file)
        else:
            os.system('rm -rf %s/*' % (capture_file))
    if runtime_starttime == "":
        runtime_starttime='1 min ago'
    if runtime_endtime == "":
        runtime_endtime='now'
    if release == "":
        release='19B'
    print('Capture file is {}!'.format(capture_file))
    capture_all_log(bts_s1ip, domain_slot, capture_file, release,
                    l2_file=os.path.join(capture_file, 'capture.bin'),                
                    l2_log_duration='30',
                    l1_registers_file=os.path.join(capture_file, 'l1_registers.log'),
                    l1_registers_log_duration='60',
                    runtime_file=os.path.join(capture_file, 'runtime.log'),
                    runtime_starttime=runtime_starttime,
                    runtime_endtime=runtime_endtime)