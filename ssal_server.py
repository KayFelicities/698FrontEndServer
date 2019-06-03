import socketserver
import logging
import binascii
import pathlib
import sys
import time

logging.basicConfig(level=logging.INFO, 
                    format='[%(asctime)s %(levelname)s]%(message)s',
                    handlers=[logging.StreamHandler(),
                    logging.FileHandler(f"{pathlib.Path(sys.argv[0]).name}.log", encoding="utf-8"),
                    ],
)

class Msg():
    def __init__(self, msg):
        if isinstance(msg, bytes):
            self.msg_bytes = msg
            self.msg_list = [f'{x:02X}' for x in self.msg_bytes]
            self.msg_str = ' '.join(self.msg_list)
        elif isinstance(msg, str):
            self.msg_str = msg
            self.msg_bytes = bytearray.fromhex(self.msg_str)
            self.msg_list = [f'{x:02X}' for x in self.msg_bytes]
        elif isinstance(msg, list):
            self.msg_list = msg
            self.msg_str = ' '.join(self.msg_list)
            self.msg_bytes = bytearray.fromhex(self.msg_str)


class MyTCPHandler(socketserver.BaseRequestHandler):
    def setup(self):
        logging.info(f'{self.client_address} connected')

    def handle(self):
        # self.request is the TCP socket connected to the client
        while True:
            self.data = self.request.recv(4096)
            if not self.data:
                break
            msg = Msg(self.data)
            if msg.msg_list[7] == 'C1': # login & heartbeat
                logging.info(f'recv login: {msg.msg_str}')
                re_msg = Msg('986500FFFF80FF41011001080602000000010004C81EA8C0044E0AA8C0264E0AA8C0BE1307E20B0C0E172304740AA8C0fcb932006830000105010000000000D1561E81008007E30313020F3A1502D007E30313020F3815000007E30313020F38150000E25C168e0b16')
                self.request.sendall(re_msg.msg_bytes)
                if msg.msg_list[-19] == '00': # login
                    time.sleep(.1)
                    get_info_msg = Msg('98 33 00 FF FF 80 FF 42 01 10 01 08 06 02 00 00 00 01 00 04 C8 1E A8 C0 04 4E 0A A8 C0 26 4E 0A A8 C0 BE 13 07 E2 0B 0C 0E 17 23 04 74 0A A8 C0 37 C9 00 00 DE FC 16')
                    self.request.sendall(get_info_msg.msg_bytes)
            else:
                logging.warning(f'skip msg: {msg.msg_str}')

    def finish(self):
        logging.info(f'{self.client_address} quit')


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 20084
    with socketserver.ThreadingTCPServer((HOST, PORT), MyTCPHandler) as server:
        server.serve_forever()
