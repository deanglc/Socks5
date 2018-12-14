import asyncio
import logging
import threading
import time
from socket import AF_INET6, inet_aton, inet_ntoa, inet_ntop, inet_pton, error

logger: logging.Logger = logging.getLogger("Socks5")
_loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()


class Socks5Error(Exception):
    pass


class AuthenticationError(Socks5Error):
    pass


SUCCEEDED = 0
GENERAL_SOCKS_SERVER_FAILURE = 1
CONNECTION_NOT_ALLOWED_BY_RULESET = 2
NETWORK_UNREACHABLE = 3
HOST_UNREACHABLE = 4
CONNECTION_REFUSED = 5
TTL_EXPIRED = 6
COMMAND_NOT_SUPPORTED = 7
ADDRESS_TYPE_NOT_SUPPORTED = 8


class _Socket:

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.r = reader
        self.w = writer
        self.__socket = writer.get_extra_info('socket')
        self.__address = writer.get_extra_info('peername')

    @property
    def address(self):
        return self.__address

    @property
    def socket(self):
        return self.__socket

    async def recv(self, num: int) -> bytes:
        data = await self.r.read(num)
        return data

    async def send(self, data: bytes) -> int:
        self.w.write(data)
        await self.w.drain()
        return len(data)

    async def sockrecv(self, num: int, loop: asyncio.AbstractEventLoop) -> bytes:
        data = await loop.sock_recv(self.socket, num)
        return data

    async def socksend(self, data: bytes, loop: asyncio.AbstractEventLoop) -> int:
        await loop.sock_sendall(self.socket, data)
        return len(data)

    def close(self):
        self.w.close()


class BaseAuthentication:

    def __init__(self, socket: _Socket):
        self.socket = socket

    def getMethod(self, methods: set) -> int:
        """
        Return a allowed authentication method or 255

        Must be overwrited.
        """
        return 255

    async def authenticate(self):
        """
        Authenticate user

        Must be overwrited.
        """
        raise AuthenticationError()


class NoAuthentication(BaseAuthentication):
    """ NO AUTHENTICATION REQUIRED """

    def getMethod(self, methods: set) -> int:
        if 0 in methods:
            return 0
        return 255

    async def authenticate(self):
        pass


class PasswordAuthentication(BaseAuthentication):
    """ USERNAME/PASSWORD """

    def _getUser(self) -> dict:
        return {"AberSheeran": "password123"}

    def getMethod(self, methods: set) -> int:
        if 2 in methods:
            return 2
        return 255

    async def authenticate(self):
        VER = await self.socket.recv(1)
        if VER != 5:
            await self.socket.send(b"\x05\x01")
            raise Socks5Error("Unsupported version!")
        ULEN = int.from_bytes(await self.socket.recv(1), 'big')
        UNAME = await self.socket.recv(ULEN).decode("ASCII")
        PLEN = int.from_bytes(await self.socket.recv(1), 'big')
        PASSWD = await self.socket.recv(PLEN).decode("ASCII")
        if self._getUser().get(UNAME) and self._getUser().get(UNAME) == PASSWD:
            await self.socket.send(b"\x05\x00")
        else:
            await self.socket.send(b"\x05\x01")
            raise AuthenticationError("USERNAME or PASSWORD ERROR")


class BaseSessoin:
    """
    Client session
    """

    def __init__(self, socket: _Socket):
        self.socket = socket
        self.auth = BaseAuthentication(self.socket)

    async def recv(self, num: int) -> bytes:
        data = await self.socket.recv(num)
        logger.debug(f"<<< {data}")
        if not data:
            raise ConnectionError("Recv a empty bytes that may FIN or RST")
        return data

    async def send(self, data: bytes) -> int:
        length = await self.socket.send(data)
        logger.debug(f">>> {data}")
        return length

    async def start(self):
        try:
            await self.negotiate()
        # 协商过程中出现Socks5不允许的情况
        except Socks5Error as e:
            logger.warning(e)
            self.socket.close()
        # 协商过程中发生网络错误
        except (ConnectionError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError) as e:
            logger.error(e)
            self.socket.close()

    async def negotiate(self):
        data = await self.recv(2)
        VER, NMETHODS = data
        if VER != 5:
            await self.send(b"\x05\xff")
            raise Socks5Error("Unsupported version!")
        METHODS = set(await self.recv(NMETHODS))
        METHOD = self.auth.getMethod(METHODS)
        reply = b'\x05' + METHOD.to_bytes(1, 'big')
        await self.send(reply)
        if METHOD == 255:
            raise Socks5Error("No methods available")
        await self.auth.authenticate()
        data = await self.recv(4)
        VER, CMD, RSV, ATYP = data
        if VER != 5:
            await self.reply(GENERAL_SOCKS_SERVER_FAILURE)
            raise Socks5Error("Unsupported version!")
        # Parse target address
        if ATYP == 1:  # IPV4
            ipv4 = await self.recv(4)
            DST_ADDR = inet_ntoa(ipv4)
        elif ATYP == 3:  # Domain
            addr_len = int.from_bytes(await self.recv(1), byteorder='big')
            DST_ADDR = (await self.recv(addr_len)).decode()
        elif ATYP == 4:  # IPV6
            ipv6 = await self.recv(16)
            DST_ADDR = inet_ntop(AF_INET6, ipv6)
        else:
            await self.reply(ADDRESS_TYPE_NOT_SUPPORTED)
            raise Socks5Error(f"Unsupported ATYP value: {ATYP}")
        DST_PORT = int.from_bytes(await self.recv(2), 'big')
        if CMD == 1:
            await self.socks5_connect(ATYP, DST_ADDR, DST_PORT)
        elif CMD == 2:
            await self.socks5_bind(ATYP, DST_ADDR, DST_PORT)
        elif CMD == 3:
            await self.socks5_udp_associate(ATYP, DST_ADDR, DST_PORT)
        else:
            await self.reply(COMMAND_NOT_SUPPORTED)
            raise Socks5Error(f"Unsupported CMD value: {CMD}")

    async def reply(self, REP: int, ATYP: int = 1, IP: str = "127.0.0.1", port: int = 1080):
        VER, RSV = b'\x05', b'\x00'
        if ATYP == 1:
            BND_ADDR = inet_aton(IP)
        elif ATYP == 4:
            BND_ADDR = inet_pton(AF_INET6, IP)
            ATYP = 4
        elif ATYP == 3:
            BND_ADDR = IP.encode("UTF-8")
        else:
            raise Socks5Error(f"Reply: unsupported ATYP value {ATYP}")
        REP = REP.to_bytes(1, 'big')
        ATYP = ATYP.to_bytes(1, 'big')
        BND_PORT = int(port).to_bytes(2, 'big')
        reply = VER + REP + RSV + ATYP + BND_ADDR + BND_PORT
        await self.send(reply)

    async def socks5_connect(self, ATYP: int, addr: str, port: int):
        """ must be overwrited """
        await self.reply(GENERAL_SOCKS_SERVER_FAILURE, ATYP, addr, port)
        self.socket.close()

    async def socks5_bind(self, ATYP: int, addr: str, port: int):
        """ must be overwrited """
        await self.reply(GENERAL_SOCKS_SERVER_FAILURE, ATYP, addr, port)
        self.socket.close()

    async def socks5_udp_associate(self, ATYP: int, addr: str, port: int):
        """ must be overwrited """
        await self.reply(GENERAL_SOCKS_SERVER_FAILURE, ATYP, addr, port)
        self.socket.close()


class DefaultSession(BaseSessoin):
    """ NO AUTHENTICATION REQUIRED Session"""

    def __init__(self, socket: _Socket):
        super().__init__(socket)
        self.auth = NoAuthentication(self.socket)

    def _forward(self, sender: _Socket, receiver: _Socket):
        async def inner(sender: _Socket, receiver: _Socket):
            data = await sender.sockrecv(4096, _loop)
            if not data:
                self._disconnect(sender, receiver)
                return
            await receiver.send(data)
            logger.debug(f">=< {data}")
        asyncio.run_coroutine_threadsafe(inner(sender, receiver), _loop)

    def _connect(self, local: _Socket, remote: _Socket):
        _loop.add_reader(remote.socket, self._forward, remote, local)
        _loop.add_reader(local.socket, self._forward, local, remote)

    def _disconnect(self, local: _Socket, remote: _Socket):
        _loop.remove_reader(local.socket)
        _loop.remove_reader(remote.socket)
        local.close()
        remote.close()

    async def socks5_connect(self, ATYP: int, addr: str, port: int):
        try:
            logger.info(f"Connect {addr}:{port}")
            r, w = await asyncio.open_connection(addr, port, loop=_loop)
            logger.info(f"Successfully connect {addr}:{port}")
            await self.reply(SUCCEEDED)
        except (TimeoutError, ConnectionError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError, error):
            await self.reply(CONNECTION_REFUSED)
            logger.info(f"Failing connect {addr}:{port}")
            self.socket.close()
            return
        remote = _Socket(r, w)
        self._connect(self.socket, remote)


class Socks5:
    """A socks5 server"""

    def __init__(self, IP: str = "0.0.0.0", port: int = 1080, session: BaseSessoin = DefaultSession):
        self.IP = IP
        self.port = port
        self.session = session
        self.server = _loop.run_until_complete(
            asyncio.start_server(
                self._link, self.IP, self.port, loop=_loop
            )
        )
        logger.info(f"Socks5 Server serveing on {self.server.sockets[0].getsockname()}")

    def __del__(self):
        self.server.close()
        logger.info(f"Socks5 Server has closed.")

    async def _link(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        socket = _Socket(reader, writer)
        session = self.session(socket)
        logger.debug(f"Connection from {socket.address}")
        await session.start()

    def run(self):
        threading.Thread(target=_loop.run_forever, daemon=True).start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s]-[%(asctime)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    logger.setLevel(logging.DEBUG)
    Socks5().run()
