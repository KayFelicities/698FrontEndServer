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

VERSION = 'v0.0'
DATE = '2018.03.09'
RE_MSG = '682E0001030000372310D21D81008007E2030602082E19003C07E2030602082E1A000007E2030602082E1A0000801E16'
SOFTWARE_PATH = os.path.split(os.path.realpath(__file__))[0]
CONFIG_FILE = os.path.join(SOFTWARE_PATH, '698FrontEnd.ini')
LOG_FILE = os.path.join(SOFTWARE_PATH, '698FrontEnd.log')
CLIENT_HANDLE_LIST = []
print(os.getcwd())

def msg_byte2str(byte, sep=''):
    """byte to str"""
    return sep.join(['%02X' % b for b in byte])

def msg_str2byte(hex_str):
    """str to byte"""
    hex_list = list(bytearray.fromhex(hex_str.replace(' ', '').strip()))
    return b''.join([struct.pack('B', x) for x in hex_list])


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

LOG = LoggerClass('server')


class Config():
    """server config"""
    def __init__(self):
        self.config = configparser.ConfigParser()
        if not os.path.isfile(CONFIG_FILE):
            LOG.info('config file not found, create new.')
            with open(CONFIG_FILE, 'w') as _: pass
        self.config['TerminalTcpServer'] = {}
        self.config.read(CONFIG_FILE)
        if not self.config.has_option('TerminalTcpServer', 'bind'):
            self.config['TerminalTcpServer']['bind'] = '0.0.0.0'
        if not self.config.has_option('TerminalTcpServer', 'port'):
            self.config['TerminalTcpServer']['port'] = '20083'
        if not self.config.has_option('TerminalTcpServer', 'timeout_sec'):
            self.config['TerminalTcpServer']['timeout_sec'] = '300'
        with open(CONFIG_FILE, 'w') as configfile:
            self.config.write(configfile)

    def write_config(self):
        """write config"""
        with open(CONFIG_FILE, 'w') as configfile:
            self.config.write(configfile)

    def get_terminal_bind(self):
        """get terminal bind"""
        return self.config['TerminalTcpServer']['bind']

    def get_terminal_port(self):
        """get terminal port"""
        return int(self.config['TerminalTcpServer']['port'])

    def get_terminal_timeout_sec(self):
        """get terminal tmout sec"""
        return int(self.config['TerminalTcpServer']['timeout_sec'])

CONFIG = Config()


class ClientHandler(asyncore.dispatcher_with_send):
    """client"""
    def __init__(self, *args, **kw):
        asyncore.dispatcher_with_send.__init__(self, *args, **kw)
        self.last_active_tm = time.time()
        if self not in CLIENT_HANDLE_LIST:
            CLIENT_HANDLE_LIST.append(self)

    def handle_read(self):
        data = self.recv(8192)
        if data:
            LOG.info('recv{client}:{msg}'.format(client=self.addr, msg=msg_byte2str(data)))
            self.send(msg_str2byte(RE_MSG))
            LOG.info('send{client}:{msg}'.format(client=self.addr, msg=RE_MSG))
            self.last_active_tm = time.time()
        else:
            self.handle_close()

    def handle_close(self):
        LOG.info('{client} quit'.format(client=str(self.addr)))
        self.close()
        if self in CLIENT_HANDLE_LIST:
            CLIENT_HANDLE_LIST.remove(self)

    def kill(self):
        """kill"""
        LOG.info('{client} timeout, close it.'.format(client=str(self.addr)))
        self.close()
        if self in CLIENT_HANDLE_LIST:
            CLIENT_HANDLE_LIST.remove(self)

    def is_alive(self):
        """chk client alive"""
        return True if time.time() - self.last_active_tm < CONFIG.get_terminal_timeout_sec() else False


class TcpServer(asyncore.dispatcher):
    """tcp server"""
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accepted(self, sock, addr):
        LOG.info('{client} connected'.format(client=repr(addr)))
        ClientHandler(sock)

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
        if (time.time() - chk_tm < 30):
            continue
        for client_handle in CLIENT_HANDLE_LIST:
            if not client_handle.is_alive():
                client_handle.kill()


if __name__ == '__main__':
    LOG.info('#'*30)
    LOG.info('#    698 Frontend Server     #')
    LOG.info('#  Version: {ver} {date}  #'.format(ver=VERSION, date=DATE))
    LOG.info('#      Designed by Kay       #')
    LOG.info('#'*30)
    tcp_server = TcpServer(CONFIG.get_terminal_bind(), CONFIG.get_terminal_port())
    tcp_thread = threading.Thread(name='tcp server', target=tcp_server_run)
    collection_thread = threading.Thread(name='collection', target=dead_client_kill)
    tcp_thread.start()
    collection_thread.start()
    LOG.info('Terminal TCP server start. bind {bind}, port {port}, timeout {timeout}s'\
            .format(bind=CONFIG.get_terminal_bind(), port=CONFIG.get_terminal_port(), timeout=CONFIG.get_terminal_timeout_sec()))
    while True:
        command = input('->')
        if not command:
            continue

        if command in ['i']:
            tcp_server.show_status()
        elif command in ['t']:
            print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        elif command in ['q']:
            tcp_server.close()
            asyncore.close_all()
            LOG.info('Server Quit.')
            os._exit(0)
        else:
            print('unknow command \'{cmd}\''.format(cmd=command))
