"""698Server"""
import os
import sys
import logging
import asyncore
import socket
import struct
import threading
import time
import configparser
from collections import namedtuple
import common

VERSION = 'v0.0'
DATE = '2018.03.09'
RE_MSG = '682E0001030000372310D21D81008007E2030602082E19003C07E2030602082E1A000007E2030602082E1A0000801E16'
SOFTWARE_PATH = os.path.split(os.path.realpath(__file__))[0]
CONFIG_FILE = os.path.join(SOFTWARE_PATH, '698FrontEnd.ini')
LOG_FILE = os.path.join(SOFTWARE_PATH, '698FrontEnd.log')

def msgbyte2str(byte, sep=''):
    """byte to str"""
    return sep.join(['%02X' % b for b in byte])

def msgbyte2strlist(byte):
    """byte to str"""
    return ['%02X' % b for b in byte]

def msgstr2byte(hex_str):
    """str to byte"""
    hex_list = list(bytearray.fromhex(hex_str.replace(' ', '').strip()))
    return b''.join([struct.pack('B', x) for x in hex_list])

def msgstr2list(msgstr):
    """str to list"""
    msgstr = msgstr.replace(' ', '').strip()[:]
    return [msgstr[pos*2:(pos+1)*2] for pos in range(len(msgstr)//2)]

def search_msg(msg):
    """search full msg and return msg text list"""
    offset = 0
    m_list = msgstr2list(msg)
    msg_list = []
    while offset < len(m_list) - 5:  # at least 5 byte
        if m_list[offset] == '68':
            msg_len = int(m_list[offset + 2] + m_list[offset + 1], 16)
            if offset + msg_len + 1 < len(m_list) and m_list[offset + msg_len + 1] == '16':
                msg_list.append(''.join(m_list[offset: offset + msg_len + 2]))
                offset += msg_len + 2
            else:
                offset += 1
        else:
            offset += 1
    return msg_list

def get_reply_heart_msg(in_tm_str, SA, CA, piid):
    """reply"""
    tm_local = time.localtime()
    weekday = 0 if tm_local.tm_wday == 6 else tm_local.tm_wday + 1 
    tm2_text = '%04X %02X %02X %02X %02X %02X %02X 0000'\
                    % (tm_local[0], tm_local[1], tm_local[2],\
                        weekday, tm_local[3], tm_local[4], tm_local[5])
    reply_apdu_text = '81 %s %s'%(piid, '80') + in_tm_str + tm2_text + tm2_text
    return common.add_linkLayer(msgstr2list(reply_apdu_text), CA, SA, C_text='01')


class LoggerClass():
    """logger"""
    def __init__(self, log_name):
        self.logger = logging.getLogger(log_name)
        formatter = logging.Formatter('[%(asctime)s] %(message)s')
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        self.logger.setLevel(logging.INFO)

    def info(self, *msg):
        """log info"""
        self.logger.info(*msg)

    def recv_tmn_link_msg(self, tmn_SA, tmn_addr, msg, link_type='heart'):
        """recv_tmn_link_msg"""
        self.logger.info('{link_type} from T[{SA}({t_ip})]:{msg}'\
            .format(link_type=link_type, SA=tmn_SA, t_ip=tmn_addr[0], msg=msg))

    def send_to_tmn(self, tmn_SA, tmn_addr, msg, from_CA='server', from_addr=('0.0.0.0', 0)):
        """send tmn msg"""
        if from_CA == 'server':
            self.logger.info('Server -> T[{SA}({t_ip})]:{msg}'\
                .format(SA=tmn_SA, t_ip=tmn_addr[0], msg=msg))
        else:
            self.logger.info('M[{CA}({m_ip})] -> T[{SA}({t_ip})]:{msg}'\
                .format(CA=from_CA, m_ip=from_addr[0], SA=tmn_SA, t_ip=tmn_addr[0], msg=msg))

    def send_to_master(self, master_CA, master_addr, msg, from_SA='server', from_addr=('0.0.0.0', 0)):
        """send tmn msg"""
        if from_SA == 'server':
            self.logger.info('Server -> M[{CA}({m_ip})]:{msg}'\
                .format(CA=master_CA, m_ip=master_addr[0], msg=msg))
        else:
            self.logger.info('T[{SA}({t_ip})] -> M[{CA}({m_ip})]:{msg}'\
                .format(SA=from_SA, t_ip=from_addr[0], CA=master_CA, m_ip=master_addr[0], msg=msg))

LOG = LoggerClass('server')


class Config():
    """server config"""
    def __init__(self):
        self.config = configparser.ConfigParser()
        if not os.path.isfile(CONFIG_FILE):
            LOG.info('config file not found, create new.')
            with open(CONFIG_FILE, 'w') as _: pass
        self.config['tmnTcpServer'] = {}
        self.config['masterTcpServer'] = {}
        self.config.read(CONFIG_FILE)
        if not self.config.has_option('tmnTcpServer', 'bind'):
            self.config['tmnTcpServer']['bind'] = '0.0.0.0'
        if not self.config.has_option('tmnTcpServer', 'port'):
            self.config['tmnTcpServer']['port'] = '20083'
        if not self.config.has_option('tmnTcpServer', 'timeout_sec'):
            self.config['tmnTcpServer']['timeout_sec'] = '300'
        if not self.config.has_option('masterTcpServer', 'bind'):
            self.config['masterTcpServer']['bind'] = '0.0.0.0'
        if not self.config.has_option('masterTcpServer', 'port'):
            self.config['masterTcpServer']['port'] = '20084'
        if not self.config.has_option('masterTcpServer', 'timeout_sec'):
            self.config['masterTcpServer']['timeout_sec'] = '300'
        with open(CONFIG_FILE, 'w') as configfile:
            self.config.write(configfile)

    def write_config(self):
        """write config"""
        with open(CONFIG_FILE, 'w') as configfile:
            self.config.write(configfile)

    def get_tmn_bind(self):
        """get tmn bind"""
        return self.config['tmnTcpServer']['bind']

    def get_tmn_port(self):
        """get tmn port"""
        return int(self.config['tmnTcpServer']['port'])

    def get_tmn_timeout_sec(self):
        """get tmn tmout sec"""
        return int(self.config['tmnTcpServer']['timeout_sec'])

    def get_master_bind(self):
        """get master bind"""
        return self.config['masterTcpServer']['bind']

    def get_master_port(self):
        """get master port"""
        return int(self.config['masterTcpServer']['port'])

    def get_master_timeout_sec(self):
        """get master tmout sec"""
        return int(self.config['masterTcpServer']['timeout_sec'])

CONFIG = Config()


class MsgChk():
    """message check"""
    def __init__(self, msg_list):
        self.msg_list = msg_list
        self.is_L_valid = True
        self.is_hcs_valid = True
        self.is_fcs_valid = True
        self.piid = ''
        self.is_login = False
        self.is_heart = False
        self.heart_cycle = 0
        self.heart_tm_str = ''
        self.is_broadcast = False
        self.logic_addr = 0
        self.SA = ''
        self.CA = ''
        self.__process(self.msg_list)

    def __process(self, msg):
        """process"""
        m_list = msgstr2list(msg)
        offset = 1
        link_length = int(m_list[offset + 1] + m_list[offset], 16)
        if link_length != len(m_list) - 2:
            self.is_L_valid = False
        offset += 2

        # 控制域
        ctrl = int(m_list[offset], 16)
        dir_prm_flag = ctrl >> 6
        frame_separation_flag = (ctrl >> 5) & 0x01
        function_flag = ctrl & 0x03
        offset += 1

        # 地址域
        if int(m_list[offset], 16) >> 6 != 0:
            self.is_broadcast = True
        self.logic_addr = (int(m_list[offset], 16) >> 4) & 0x03
        server_addr_len = (int(m_list[offset], 16) & 0x0f) + 1
        server_addr_reverse = m_list[offset + server_addr_len: offset: -1]
        self.SA = ''.join(server_addr_reverse)
        offset += server_addr_len + 1
        self.CA = '%02X'%(int(m_list[offset], 16))
        offset += 1

        # 帧头校验
        hcs_calc = common.get_fcs(m_list[1:offset])
        hcs_calc = ((hcs_calc << 8) | (hcs_calc >> 8)) & 0xffff  # 低位在前
        fcs_now = int(m_list[offset] + m_list[offset + 1], 16)
        if fcs_now != hcs_calc:
            self.is_hcs_valid = False
        offset += 2

        # 分帧
        if frame_separation_flag == 1:
            offset += 2
        
        # apdu
        if m_list[offset] in ['01', '02', '03', '10', '81', '82', '83', '84', '90', '6E', 'EE']:
            self.piid = m_list[offset + 1]
        else:
            self.piid = m_list[offset + 2]
    
        if function_flag == 1 and m_list[offset] == '01': # link
            offset += 2
            if m_list[offset] == '00':
                self.is_login = True
            else:
                self.is_heart = True
            offset += 1
            self.heart_cycle = int(m_list[offset] + m_list[offset + 1], 16)
            offset += 2
            self.heart_tm_str = ''.join(m_list[offset : offset + 10])
        
        #fcs
        fcs_calc = common.get_fcs(m_list[1:-3])
        fcs_calc = ((fcs_calc << 8) | (fcs_calc >> 8)) & 0xffff  # 低位在前
        fcs_now = int(m_list[-3] + m_list[-2], 16)
        if fcs_now != fcs_calc:
            self.is_fcs_valid = False


class UserTable():
    """tmn and master table"""
    def __init__(self):
        self.tmn_tuple = namedtuple('tmn',
                'tcp_handle ip port SA login_tm in_byte out_byte msg_in msg_out')
        self.tmn_table = []
        self.master_tuple = namedtuple('master',
                'tcp_handle ip port CA login_tm in_byte out_byte msg_in msg_out')
        self.master_table = []
        
    def __get_tmn_tuple_index(self, tcp_handle):
        """get index"""
        for index, tmn in enumerate(self.tmn_table):
            if tcp_handle == tmn.tcp_handle:
                return index
        return -1

    def get_tmn_handler_list(self, SA=''):
        """get handle list"""
        if SA:
            return [x.tcp_handle for x in self.tmn_table if x.SA == SA]
        else:
            return [x.tcp_handle for x in self.tmn_table]

    def add_tmn(self, tcp_handle, ip, port, SA, login_tm=None):
        """add tmn"""
        if login_tm is None:
            login_tm = time.time()
        index = self.__get_tmn_tuple_index(tcp_handle)
        if index >= 0:
            self.tmn_table[index] = self.tmn_table[index]._replace(ip=ip, port=port, SA=SA, login_tm=login_tm)
        else:
            self.tmn_table.append(self.tmn_tuple(tcp_handle, ip, port, SA, login_tm, 0, 0, 0, 0))

    def del_tmn(self, tcp_handle):
        """del tmn"""
        for tmn in self.tmn_table:
            if tcp_handle == tmn.tcp_handle:
                self.tmn_table.remove(tmn)
                break

    def set_tmn_SA(self, tcp_handle, SA=''):
        index = self.__get_tmn_tuple_index(tcp_handle)
        if index >= 0:
            self.tmn_table[index] = self.tmn_table[index]._replace(SA=SA)

    def update_tmn_stat(self, tcp_handle, in_byte_add=0, out_byte_add=0, in_msg_add=0, out_msg_add=0):
        index = self.__get_tmn_tuple_index(tcp_handle)
        if index >= 0:
            tmn = self.tmn_table[index]
            self.tmn_table[index] = self.tmn_table[index]._replace(in_byte=tmn.in_byte+in_byte_add,\
                out_byte=tmn.out_byte+out_byte_add, msg_in=tmn.msg_in+in_msg_add, msg_out=tmn.msg_out+out_msg_add)

    def print_tmn_table(self):
        def get_tm_str(tm):
            """tm str"""
            return time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(tm))
        fmt = '{:^15} {:^5} {:^20} {:^21} {:^9} {:^9} {:^7} {:^7}'
        print(fmt.format('tmn IP', 'port', 'SA', 'login time', 'in byte', 'out byte', 'in msg', 'out msg'))
        for tmn in self.tmn_table:
            print(fmt.format(tmn.ip, tmn.port, tmn.SA, get_tm_str(tmn.login_tm),\
                        tmn.in_byte, tmn.out_byte, tmn.msg_in, tmn.msg_out))


    def __get_master_tuple_index(self, tcp_handle):
        """get index"""
        for index, master in enumerate(self.master_table):
            if tcp_handle == master.tcp_handle:
                return index
        return -1

    def get_master_handler_list(self, CA=''):
        """get handle list"""
        if CA and CA not in ['00']:
            return [x.tcp_handle for x in self.master_table if x.CA == CA]
        else:
            return [x.tcp_handle for x in self.master_table]

    def add_master(self, tcp_handle, ip, port, CA, login_tm=None):
        """add master"""
        if login_tm is None:
            login_tm = time.time()
        index = self.__get_master_tuple_index(tcp_handle)
        if index >= 0:
            self.master_table[index] = self.master_table[index]._replace(ip=ip, port=port, CA=CA, login_tm=login_tm)
        else:
            self.master_table.append(self.master_tuple(tcp_handle, ip, port, CA, login_tm, 0, 0, 0, 0))

    def del_master(self, tcp_handle):
        """del master"""
        for master in self.master_table:
            if tcp_handle == master.tcp_handle:
                self.master_table.remove(master)
                break

    def set_master_CA(self, tcp_handle, CA=''):
        index = self.__get_master_tuple_index(tcp_handle)
        if index >= 0:
            self.master_table[index] = self.master_table[index]._replace(CA=CA)

    def update_master_stat(self, tcp_handle, in_byte_add=0, out_byte_add=0, in_msg_add=0, out_msg_add=0):
        index = self.__get_master_tuple_index(tcp_handle)
        if index >= 0:
            master = self.master_table[index]
            self.master_table[index] = self.master_table[index]._replace(in_byte=master.in_byte+in_byte_add,\
                out_byte=master.out_byte+out_byte_add, msg_in=master.msg_in+in_msg_add, msg_out=master.msg_out+out_msg_add)

    def print_master_table(self):
        def get_tm_str(tm):
            """tm str"""
            return time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(tm))
        fmt = '{:^15} {:^5} {:^20} {:^21} {:^9} {:^9} {:^7} {:^7}'
        print(fmt.format('master IP', 'port', 'CA', 'login time', 'in byte', 'out byte', 'in msg', 'out msg'))
        for master in self.master_table:
            print(fmt.format(master.ip, master.port, master.CA, get_tm_str(master.login_tm),\
                        master.in_byte, master.out_byte, master.msg_in, master.msg_out))

USER_TABLE = UserTable()


class TmnHandler(asyncore.dispatcher_with_send):
    """client"""
    def __init__(self, *args, **kw):
        asyncore.dispatcher_with_send.__init__(self, *args, **kw)
        self.last_active_tm = time.time()
        self.SA = ''
        self.msg = b''

    def handle_read(self):
        data = self.recv(8192)
        self.msg += data
        if data:
            msg_list = search_msg(msgbyte2str(self.msg))
            if not msg_list and self.msg[0] == b'\x68':
                return
            self.msg = b''
            USER_TABLE.update_tmn_stat(self, out_byte_add=len(data))
            USER_TABLE.update_tmn_stat(self, out_msg_add=len(msg_list))
            for msg in msg_list:
                msg_chk = MsgChk(msg)
                if msg_chk.is_login or msg_chk.is_heart:
                    self.SA = msg_chk.SA
                    USER_TABLE.set_tmn_SA(self, msg_chk.SA)
                    LOG.recv_tmn_link_msg(msg_chk.SA, self.addr, msg, 'login' if msg_chk.is_login else 'heart')
                    reply_msg = get_reply_heart_msg(msg_chk.heart_tm_str, msg_chk.SA, msg_chk.CA, msg_chk.piid)
                    reply_byte = msgstr2byte(reply_msg)
                    self.send(reply_byte)
                    LOG.send_to_tmn(msg_chk.SA, self.addr, reply_msg)
                    USER_TABLE.update_tmn_stat(self, in_byte_add=len(reply_byte))
                    USER_TABLE.update_tmn_stat(self, in_msg_add=1)
                else:
                    send_list = USER_TABLE.get_master_handler_list(CA=msg_chk.CA)
                    if send_list:
                        for master_handle in send_list:
                            master_handle.send_msg(msg, self.SA, self.addr)
                    else:
                        LOG.send_to_master(msg_chk.CA, ('None', 0), msg, self.SA, self.addr)
            self.last_active_tm = time.time()
        else:
            self.handle_close()

    def handle_close(self):
        LOG.info('tmn({ip}:{port}) quit'.format(ip=self.addr[0], port=self.addr[1]))
        self.close()
        USER_TABLE.del_tmn(self)

    def send_msg(self, msg, from_CA, from_addr):
        """send msg to tmn"""
        self.send(msgstr2byte(msg))
        LOG.send_to_tmn(self.SA, self.addr, msg, from_CA, from_addr)
        USER_TABLE.update_tmn_stat(self, in_byte_add=len(msgstr2byte(msg)))
        USER_TABLE.update_tmn_stat(self, in_msg_add=1)

    def kill(self):
        """kill"""
        LOG.info('tmn({ip}:{port}) timeout, close it'.format(ip=self.addr[0], port=self.addr[1]))
        self.close()
        USER_TABLE.del_tmn(self)

    def is_alive(self):
        """chk client alive"""
        return True if time.time() - self.last_active_tm < CONFIG.get_tmn_timeout_sec() else False


class TmnTcpServer(asyncore.dispatcher):
    """tcp server"""
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accepted(self, sock, addr):
        LOG.info('tmn({ip}:{port}) connected'.format(ip=addr[0], port=addr[1]))
        handler = TmnHandler(sock)
        USER_TABLE.add_tmn(handler, addr[0], addr[1], '')

    def show_status(self):
        """show status"""
        for no, thread in self._map.items():
            print('{no}|{thread}'.format(no=no, thread=thread))


class MasterHandler(asyncore.dispatcher_with_send):
    """master tcp handle"""
    def __init__(self, *args, **kw):
        asyncore.dispatcher_with_send.__init__(self, *args, **kw)
        self.last_active_tm = time.time()
        self.CA = ''
        self.msg = b''

    def handle_read(self):
        data = self.recv(8192)
        self.msg += data
        if data:
            msg_list = search_msg(msgbyte2str(self.msg))
            if not msg_list and self.msg[0] == b'\x68':
                return
            self.msg = b''
            USER_TABLE.update_master_stat(self, out_byte_add=len(data))
            USER_TABLE.update_master_stat(self, out_msg_add=len(msg_list))
            for msg in msg_list:
                msg_chk = MsgChk(msg)
                send_list = USER_TABLE.get_tmn_handler_list(SA='' if msg_chk.is_broadcast else msg_chk.SA)
                if send_list:
                    self.CA = msg_chk.CA
                    USER_TABLE.set_master_CA(self, msg_chk.CA)
                    for tmn_handle in send_list:
                        tmn_handle.send_msg(msg, self.CA, self.addr)
                else:
                    LOG.send_to_tmn(msg_chk.SA, ('None', 0), msg, self.CA, self.addr)
            self.last_active_tm = time.time()
        else:
            self.handle_close()

    def handle_close(self):
        LOG.info('master({ip}:{port}) quit'.format(ip=self.addr[0], port=self.addr[1]))
        self.close()
        USER_TABLE.del_master(self)

    def send_msg(self, msg, from_SA, from_addr):
        """send msg to master"""
        self.send(msgstr2byte(msg))
        LOG.send_to_master(self.CA, self.addr, msg, from_SA, from_addr)
        USER_TABLE.update_master_stat(self, in_byte_add=len(msgstr2byte(msg)))
        USER_TABLE.update_master_stat(self, in_msg_add=1)

    def kill(self):
        """kill"""
        LOG.info('master({ip}:{port}) timeout, close it.'.format(ip=self.addr[0], port=self.addr[1]))
        self.close()
        USER_TABLE.del_master(self)

    def is_alive(self):
        """chk client alive"""
        return True if time.time() - self.last_active_tm < CONFIG.get_master_timeout_sec() else False


class MasterTcpServer(asyncore.dispatcher):
    """tcp server"""
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accepted(self, sock, addr):
        LOG.info('master({ip}:{port}) connected'.format(ip=addr[0], port=addr[1]))
        handler = MasterHandler(sock)
        USER_TABLE.add_master(handler, addr[0], addr[1], '')

    def show_status(self):
        """show status"""
        for no, thread in self._map.items():
            print('{no}|{thread}'.format(no=no, thread=thread))


def tcp_server_run():
    """run server"""
    asyncore.loop()


def dead_client_kill():
    """collection"""
    chk_tm = time.time()
    while True:
        time.sleep(1)
        if time.time() - chk_tm < 30:
            continue
        for client_handle in USER_TABLE.get_tmn_handler_list():
            if not client_handle.is_alive():
                client_handle.kill()


if __name__ == '__main__':
    LOG.info('#'*30)
    LOG.info('#    698 Frontend Server     #')
    LOG.info('#  Version: {ver} {date}  #'.format(ver=VERSION, date=DATE))
    LOG.info('#      Designed by Kay       #')
    LOG.info('#'*30)
    tmn_tcp_server = TmnTcpServer(CONFIG.get_tmn_bind(), CONFIG.get_tmn_port())
    master_tcp_server = MasterTcpServer(CONFIG.get_master_bind(), CONFIG.get_master_port())
    tcp_server_thread = threading.Thread(name='tcp server', target=tcp_server_run)
    collection_thread = threading.Thread(name='collection', target=dead_client_kill)
    tcp_server_thread.start()
    collection_thread.start()
    LOG.info('terminal server bind {bind}, port {port}, timeout {timeout}s'\
            .format(bind=CONFIG.get_tmn_bind(), port=CONFIG.get_tmn_port(), timeout=CONFIG.get_tmn_timeout_sec()))
    LOG.info('master server bind {bind}, port {port}, timeout {timeout}s'\
            .format(bind=CONFIG.get_master_bind(), port=CONFIG.get_master_port(), timeout=CONFIG.get_master_timeout_sec()))
    while True:
        command = input('->')
        if not command:
            continue

        if command in ['i']:
            print('*'*16, 'Terminal list', '*'*16)
            USER_TABLE.print_tmn_table()
            print('')
            print('*'*16, 'Master list', '*'*16)
            USER_TABLE.print_master_table()
        elif command in ['ii']:
            tmn_tcp_server.show_status()
        elif command in ['t']:
            print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        elif command in ['q']:
            tmn_tcp_server.close()
            master_tcp_server.close()
            asyncore.close_all()
            LOG.info('Server Quit.')
            os._exit(0)
        else:
            print('unknow command \'{cmd}\''.format(cmd=command))
