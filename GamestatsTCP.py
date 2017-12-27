#! /usr/bin/env python
"""Dummy GameSpy's gamestats server.

Work on both Python2 and Python3.

Usage:
    python GamestatsTCP.py [IP address] [Port]
"""

import os
import logging
from logging.handlers import TimedRotatingFileHandler

import sys
import select
try:
    # Python2
    import SocketServer
except ImportError:
    # Python3
    import socketserver as SocketServer

import GamestatsDatabase

LOG_DIR = "logs"
LOG_FILE = True
LOG_CONSOLE = True

TIMEOUT_IN_SEC = 21.0


def get_logger():
    """Generate a logger."""
    logger = logging.getLogger("GamestatsTCP")
    logger.setLevel(-1)
    formatter = logging.Formatter("[%(asctime)s | GamestatsTCP] %(message)s",
                                  datefmt="%Y-%m-%d %H:%M:%S")

    if LOG_CONSOLE:
        console_logger = logging.StreamHandler()
        console_logger.setFormatter(formatter)
        logger.addHandler(console_logger)

    if LOG_FILE:
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
        file_logger = TimedRotatingFileHandler(
            os.path.join(LOG_DIR, "gamestats_tcp.log"),
            when='midnight',
            backupCount=21
        )
        file_logger.setFormatter(formatter)
        logger.addHandler(file_logger)

    return logger


g_logger = get_logger()


class GamestatsTCPHandler(SocketServer.BaseRequestHandler):
    """Basic dummy TCP handler."""
    GAMESTATS_KEYS = [
        b"GameSpy3D",
        b"Industries",
        b"ProjectAphex"
    ]

    def crypt(self, data, key=GAMESTATS_KEYS[0]):
        """Gamestats XOR."""
        key = bytearray(key)
        key_len = len(key)
        output = bytearray(data)
        end = output.index(b"\\final\\") \
            if b"\\final\\" in output \
            else len(output)
        for i in range(end):
            output[i] ^= key[i % key_len]
        return output

    def send(self, data):
        """Send data."""
        return self.request.send(self.crypt(data))

    def recv(self, size=1024):
        """Receive data."""
        return self.crypt(self.request.recv(size))

    def log(self, message, parameters=[], session={},
            level=logging.DEBUG):
        """Log message."""
        g_logger.log(level, "%s | parameters=%s, session=%s",
                     message, parameters, session)

    def log_send(self, message, parameters=[], session={},
                 level=logging.DEBUG):
        """Log sended message."""
        self.log("  To: {} | {}".format("{}:{}".format(*self.client_address),
                                        message), parameters, session, level)

    def log_recv(self, message, parameters=[], session={},
                 level=logging.DEBUG):
        """Log received message."""
        self.log("From: {} | {}".format("{}:{}".format(*self.client_address),
                                        message), parameters, session, level)

    def log_with(self, message, parameters=[], session={},
                 level=logging.DEBUG):
        """Log client message."""
        self.log("With: {} | {}".format("{}:{}".format(*self.client_address),
                                        message), parameters, session, level)

    def parse(self, data):
        """Parse gamespy message."""
        ls = data[:data.index(b'\\final\\')].strip(b'\\').split(b'\\')
        if len(ls) % 2:
            # MUST BE EVEN!
            g_logger.log(logging.ERROR, "Not even gamespy message\n -> %s",
                         data)
            ls.append(b'')
        ls = [bytes(i) for i in ls]
        gs = list(zip(ls[0::2], ls[1::2]))
        return gs[0], gs[1:]

    def send_lc1(self, parameters=[], session={}):
        r"""Send login challenge 1.

        Format: \*\*\challenge\%s\id\%s
         - *: ignored
         - challenge: random 8-byte string
         - id: identifier
        """
        session.update(parameters)
        challenge = session.get(b"challenge", b"WOMBOCOMBO")
        id = session.get(b"id", b"1")
        session.update({
            b"challenge": challenge,
            b"id": id
        })

        message = b"".join([
            b"\\lc\\1",
            b"\\challenge\\", challenge,
            b"\\id\\", id,
            b"\\final\\"
        ])
        self.log_send("{}".format(message), parameters, session)
        return self.send(message)

    def send_lc2(self, parameters=[], session={}):
        r"""Send login challenge 2.

        Format: \*\*\sesskey\%d\id\%d
         - *: ignored
         - sesskey: session identifier
         - id: identifier

        Ignored format:
         - proof: (unused)
        """
        session.update(parameters)
        sesskey = session.get(b"sesskey", b"4212342321")
        proof = session.get(b"proof", b"0")
        id = session.get(b"id", b"1")
        session.update({
            b"sesskey": sesskey,
            b"proof": proof,
            b"id": id
        })

        message = b"".join([
            b"\\lc\\2",
            b"\\sesskey\\", sesskey,
            # b"\\proof\\", proof,
            b"\\id\\", id,
            b"\\final\\"
        ])
        self.log_send("{}".format(message), parameters, session)
        return self.send(message)

    def send_pauthr(self, parameters=[], session={}):
        r"""Send authp response.

        Format: \pauthr\%d\lid\%d
         - pauthr: player id
         - lid: local id
        """
        session.update(parameters)
        # TODO: Replace pauthr with profile id associated to the authtoken
        try:
            # Wiimmfi profile id
            _, profile_id, _, _, _ = session[
                b"authtoken"
            ].split(b"|")[0].split(b"/")
            session.update({
                b"pauthr": profile_id,
                b"is_wiimmfi": True
            })
        except:
            # Dummy profile id = 42123
            self.log("Not a Wiimmfi authtoken", parameters, session)
        pauthr = session.get(b"pauthr", b"42123")
        lid = session.get(b"lid", b"0")
        session.update({
            b"pauthr": pauthr,
            b"lid": lid
        })

        message = b"".join([
            b"\\pauthr\\", pauthr,
            b"\\lid\\", lid,
            b"\\final\\"
        ])
        self.log_send("{}".format(message), parameters, session)
        return self.send(message)

    def send_getpdr(self, parameters=[], session={}):
        r"""Send getpd response.

        Format: \getpdr\%d\lid\%d\pid\%d\mod\%d\length\%d\data\
         - getpdr:
           * 1 - on success
           * 2 - if not modified since the time requested
           * < 1 - otherwise
         - lid: local id
         - pid: player id
         - mod: modified since
         - length: data length
         - data: player data
        """
        session.update(parameters)
        keys = [key for key in session[b"keys"].split(b"\x01") if key]

        try:
            getpdr, data, mod = GamestatsDatabase.get_data(
                session[b"gamename"], session[b"pid"], session[b"dindex"],
                session[b"ptype"], keys, session.get(b"mod", 0),
                session.get(b"is_wiimmfi"), session.get(b"pauthr")
            )
        except Exception as e:
            getpdr, data, mod = 0, b"", 0
            self.log(
                "GetData: {}".format(str(e)),
                parameters, session, logging.ERROR
            )

        message = b"".join([
            b"\\getpdr\\", str(getpdr).encode("ascii"),
            b"\\lid\\", session[b"lid"],
            b"\\pid\\", session[b"pid"],
            b"\\mod\\", str(mod).encode("ascii"),
            b"\\length\\", str(len(data)).encode('ascii'),
            b"\\data\\", data,
        ])
        message += message.count(b'\\') % 2 * b"\\" + b"\\final\\"
        self.log_send("{}".format(message), parameters, session)
        return self.send(message)

    def send_setpdr(self, parameters=[], session={}):
        r"""Send setpd response.

        Format: \setpdr\%d\lid\%d\pid\%d\mod\%d
         - setpdr:
           * 1 - on success
           * < 1 - otherwise
         - lid: local id
         - pid: player id
         - mod: modified since
        """
        data_index = parameters.index((b"data", b""))
        session.update(parameters[:data_index])
        key_values = parameters[data_index + 1:]

        try:
            setpdr, mod = GamestatsDatabase.set_data(
                session[b"gamename"], session[b"pid"], session[b"dindex"],
                session[b"ptype"], session[b"kv"], key_values,
                session.get(b"is_wiimmfi"), session.get(b"pauthr")
            )
        except Exception as e:
            setpdr, mod = 0, 0
            self.log(
                "SetData: {}".format(str(e)),
                parameters, session, logging.ERROR
            )

        message = b"".join([
            b"\\setpdr\\", str(setpdr).encode("ascii"),
            b"\\lid\\", session[b"lid"],
            b"\\pid\\", session[b"pid"],
            b"\\mod\\", str(mod).encode("ascii"),
            b"\\final\\"
        ])
        self.log_send("{}".format(message), parameters, session)
        return self.send(message)

    def handle_error(self, command, parameters=[], session={}):
        """Handle unknown command."""
        self.log_recv("{}, unsupported command".format(command),
                      parameters, session)
        return

    def handle_auth(self, parameters=[], session={}):
        r"""Handle authentication.

        Format: \auth\\gamename\%s\response\%s\port\%d\id\1
         - gamename: gcd gamename
         - response: challenge response
         - port: server port (0 by default)
        """
        self.log_recv("auth", parameters, session)
        return self.send_lc2(parameters, session)

    def handle_authp(self, parameters=[], session={}):
        r"""Handle player authentication.

        Format: \authp\\authtoken\%s\resp\%s\lid\%d
         - authtoken: authentication token
         - resp: challenge response
         - lid: local id

        Format: \authp\\pid\%d\resp\%s\lid\%d
         - pid: player id
         - resp: challenge response
         - lid: local id

        Format: \authp\\nick\%s\keyhash\%s\resp\%s\lid\%d
         - nick: player nickname
         - keyhash: hash of the player's CD key
         - resp: challenge response
         - lid: local id
        """
        self.log_recv("authp", parameters, session)
        return self.send_pauthr(parameters, session)

    def handle_ka(self, parameters=[], session={}):
        r"""Handle keep-alive.

        Format: \ka\\final\
        """
        self.log_recv("ka", parameters, session)
        return self.send(b'\\ka\\\\final\\')

    def handle_getpd(self, parameters=[], session={}):
        r"""Handle get player data.

        Format: \getpd\\pid\%d\ptype\%d\dindex\%d\keys\%s\lid\%d
         - pid: player id
         - ptype: persistant data type
            0 - pd_private_ro:
              * Readable only by the authenticated client it belongs to.
              * It can only be set on the server.
            1 - pd_private_rw:
              * Readable only by the authenticated client it belongs to.
              * Set by the authenticated client it belongs to.
            2 - pd_public_ro:
              * Readable by any client.
              * It can only be set on the server.
            3 - pd_public_rw:
              * Readable by any client.
              * Set by the authenicated client it belongs to.
         - dindex: persistant data index
         - keys: keys separated by '\x01' character
         - lid: local id

        Optional format: \mod\%d
         - mod: modified since
        """
        self.log_recv("getpd", parameters, session)
        return self.send_getpdr(parameters, session)

    def handle_setpd(self, parameters=[], session={}):
        r"""Handle set player data.

        Format: \setpd\\pid\%d\ptype\%d\dindex\%d\kv\%d\lid\%d\length\%d\data\
         - pid: player id
         - ptype: persistant data type
            0 - pd_private_ro:
              * Readable only by the authenticated client it belongs to.
              * It can only be set on the server.
            1 - pd_private_rw:
              * Readable only by the authenticated client it belongs to.
              * Set by the authenticated client it belongs to.
            2 - pd_public_ro:
              * Readable by any client.
              * It can only be set on the server.
            3 - pd_public_rw:
              * Readable by any client.
              * Set by the authenicated client it belongs to.
         - dindex: persistant data index
         - kv: only update provided key-values if set
         - lid: local id
         - length: data length + 1 (including nul byte)
         - data: player data
           * example: \key1\value1\key2\value2
        """
        self.log_recv("setpd", parameters, session)
        return self.send_setpdr(parameters, session)

    def handle(self):
        """Handle TCP requests."""
        HANDLERS = {
            b'auth':  self.handle_auth,
            b'authp': self.handle_authp,
            b'ka':    self.handle_ka,
            b'getpd': self.handle_getpd,
            b'setpd': self.handle_setpd
        }
        self.log_recv("Connection established!")
        session = {}
        self.send_lc1([], session)

        message = b''
        while select.select([self.request], [], [], TIMEOUT_IN_SEC)[0]:
            data = self.recv()
            if not data:
                break

            message += data
            if b"\\final\\" not in message:
                continue

            (command, _), parameters = self.parse(message)
            if command in HANDLERS:
                HANDLERS[command](parameters, session)
            else:
                self.handle_error(command, parameters, session)
            message = b''
        self.log_send("Connection terminated!", session=session)


if __name__ == "__main__":
    """Usage:  python GamestatsTCP [IP address] [Port]"""
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 29920
    server = SocketServer.ThreadingTCPServer((host, port), GamestatsTCPHandler)
    try:
        with GamestatsDatabase.WiimmfiGamestatsDatabase() as db:
            db.init()
        g_logger.log(logging.DEBUG, "Server: {} | Port: {}".format(host, port))
        server.serve_forever()
    except KeyboardInterrupt:
        g_logger.log(logging.DEBUG, "[Server] Closing...")
        server.server_close()
