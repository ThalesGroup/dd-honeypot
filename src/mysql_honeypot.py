import logging
import socket
import threading
import struct

from src.base_honeypot import BaseHoneypot

logger = logging.getLogger(__name__)

class MySqlHoneypot(BaseHoneypot):
    def __init__(self):
        super().__init__()
        self.server_socket = None
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()
        logger.info(f"MySQL Honeypot started on port {self.port}")

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                logger.warning(f"Error closing socket: {e}")
        logger.info("MySQL Honeypot stopped")

    def _run_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("localhost", self.port))
            self.server_socket.listen(5)

            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    logger.info(f"Accepted connection from {addr}")
                    threading.Thread(target=self._handle_client, args=(client_socket,), daemon=True).start()
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
        except Exception as e:
            logger.error(f"Failed to start honeypot server: {e}")

    def _handle_login(self, client_sock):
        try:
            login_packet = client_sock.recv(1024)
            if not login_packet:  # Handle empty packet
                print("[!] Empty login packet received")
                return False

            print(f"[>] Login request: {login_packet.hex()}")

            # Modern MySQL clients expect caching_sha2_password
            ok_packet = (
                    b'\x07\x00\x00\x02' +  # length and packet number
                    b'\x00' +  # OK packet identifier
                    b'\x00\x00\x00' +  # affected rows
                    b'\x02\x00\x00\x00'  # server status
            )
            client_sock.sendall(ok_packet)
            return True

        except ConnectionResetError:
            print("[!] Client reset connection during login")
            return False
        except Exception as e:
            print(f"[!] Login error: {e}")
            return False

    def _handle_client(self, client_sock):
        try:
            if not self._send_handshake(client_sock):
                return

            if not self._handle_login(client_sock):
                return

            self._handle_queries(client_sock)
        except Exception as e:
            print(f"[!] Client handling error: {e}")
        finally:
            client_sock.close()



    def _build_handshake_packet(self):
        auth_plugin_data_part_1 = b'abcdefgh'
        auth_plugin_data_part_2 = b'ijklmnopqrst'  # make sure total = 13 bytes at least

        payload = (
                b'\x0a' +  # Protocol version
                b'5.7.0-honeypot\x00' +  # Server version
                struct.pack('<I', 1234) +  # Connection ID
                auth_plugin_data_part_1 + b'\x00' +  # Auth plugin data part 1 + filler
                struct.pack('<H', 0xffff) +  # Capability flags (lower)
                b'\x21' +  # Character set
                struct.pack('<H', 2) +  # Status flags
                struct.pack('<H', 0xffff) +  # Capability flags (upper)
                bytes([len(auth_plugin_data_part_1 + auth_plugin_data_part_2)]) +  # Auth plugin data length
                b'\x00' * 10 +  # Reserved
                auth_plugin_data_part_2 + b'\x00' +  # Auth plugin data part 2 + null-term
                b'mysql_native_password\x00'  # Auth plugin name
        )

        length = struct.pack('<I', len(payload))[:3]
        return length + b'\x00' + payload

    def _build_ok_packet(self, packet_id):
        payload = (
            b'\x00' +               # OK packet header
            b'\x00' +               # Affected rows
            b'\x00' +               # Last insert ID
            b'\x02\x00' +           # Server status (autocommit)
            b'\x00\x00'             # Warnings
        )
        length = struct.pack('<I', len(payload))[:3]
        return length + struct.pack("B", packet_id) + payload

    def _build_fake_select_response(self, start_packet_id):
        def wrap(payload, packet_id):
            return struct.pack('<I', len(payload))[:3] + struct.pack('B', packet_id) + payload

        packets = []
        packet_id = start_packet_id

        # Column count (1)
        packets.append(wrap(b'\x01', packet_id))
        packet_id += 1

        # Column definition
        col_def = (
            b'\x03def' + b'\x00'*4 +
            b'\x01' + b'c' +
            b'\x01' + b'c' +
            b'\x0c' +
            struct.pack('<H', 33) +
            struct.pack('<I', 1) +
            b'\x03' +
            struct.pack('<H', 0) +
            b'\x00' +
            b'\x00\x00'
        )
        packets.append(wrap(col_def, packet_id))
        packet_id += 1

        # EOF after column definition
        packets.append(wrap(b'\xfe\x00\x00\x02\x00', packet_id))
        packet_id += 1

        # No row data (empty result set)

        # Final EOF
        packets.append(wrap(b'\xfe\x00\x00\x02\x00', packet_id))
        return packets
