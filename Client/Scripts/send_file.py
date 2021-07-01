import binascii
import hashlib
import multiprocessing as mp
import os
import socket as sock
import ssl
import struct
import threading
import time
from multiprocessing import shared_memory, Queue as mpQueue
from threading import Lock

mp.allow_connection_pickling()


class SyncFolder:
    current_file_upload_progress = None
    current_file_upload_buffer = 8192

    lock = Lock()

    def __init__(self):
        self._send_start_time = 0

    def __int__(self, folder_path):
        pass

    @staticmethod
    def start_thread(target, *args, daemon=False):
        thread = threading.Thread(
            target=target,
            args=args,
            daemon=daemon
        )
        thread.start()
        return thread

    @staticmethod
    def file_md5(fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def _socket_sendfile(self, socket, file, offset, count):
        blocksize = min(count, 8192) if count else 8192
        total_sent = 0
        # localize variable access to minimize overhead
        file_read = file.read
        sock_send = socket.send
        while True:
            blocksize = min(count - total_sent, blocksize)
            if blocksize <= 0:
                break
            # with self.lock:
            file.seek(offset + total_sent)
            data = memoryview(file_read(blocksize))
            if not data:
                break  # EOF

            while True:
                try:
                    sent = sock_send(data)
                except BlockingIOError:
                    continue
                else:
                    total_sent += sent
                    self._sent_bytes = total_sent # # #
                    t = time.time() - self._send_start_time - 0.00000000000001
                    s = total_sent / 1048576
                    print(f'Sending time: {t} seconds ({s} MB).   Speed: {s / t} MB/s', end='\r')
                    if sent < len(data):
                        data = data[sent:]
                    else:
                        break
        # s_print('total_sent:', total_sent)
        return total_sent

    def _send_file(self, file, offset, step_size, buffer_size, ip, port, progress=None):
        def no_connection():
            print("No connection to server!")
            self._send_start_time = time.time()
            self._sent_bytes = 0

        addr = (ip, port)
        print(addr)
        with sock.socket(sock.AF_INET, sock.SOCK_STREAM, sock.IPPROTO_TCP) as tcp_socket:
            # tcp_socket.settimeout(10)
            try:
                print("connecting...")
                tcp_socket.connect(addr)
            except ConnectionRefusedError:
                no_connection()
                return
            except TimeoutError:
                no_connection()
                return

            tcp_socket.sendall(struct.pack('>q', buffer_size)) # long long (8 bytes == 64 bits)
            tcp_socket.sendall(struct.pack('>q', step_size))
            # r = range(buffer_size, step_size, buffer_size)
            if self._send_start_time == 0:
                self._send_start_time = time.time()
            try:
                self._socket_sendfile(tcp_socket, file, offset, step_size)
                self._sent_bytes = tcp_socket.sendfile(file, offset, step_size)
            except ConnectionResetError:
                print("Connection closed!")
                return
            except ConnectionAbortedError:
                print("Connection aborted!")
                return
            # for sent in r:
            #     if buffer_size != self._socket_sendfile(tcp_socket, file, offset, step_size):
            #         self._sent_bytes = sent
            #         return
            #     else:
            #         offset += buffer_size
            if progress:
                progress.update(buffer_size)

            end_time = round(time.time() - self._send_start_time, 5)
            if end_time == 0:
                end_time = 0.01
            print('Sending time: {} seconds\nSpeed: {} MB/s'.format(
                    end_time, (self._sent_bytes / end_time) / (1024 * 1024)))

            # last_bytes = step_size - r[-1] # step_size - int(step_size / buffer_size) * buffer_size
            # print(last_bytes, r[-1])
            # if last_bytes != 0:
            #     self._socket_sendfile(tcp_socket, file, offset, last_bytes)
            #     if progress:
            #         progress.update(step_size - last_bytes)

    def send_file(self, filename: str, buffer_size: int, n_slices: int, ip: str, port: int):
        filesize = os.path.getsize(filename)
        print(filesize)
        threads = list()
        with open(filename, 'rb', buffering=buffer_size) as file:
            step = int(filesize / n_slices) + 1
            print(step)
            self.current_file_upload_progress = None# tqdm.tqdm(range(filesize), f"Sending {filepath}", unit="B",
                                                #          unit_scale=True, unit_divisor=1024, smoothing=0.0)
            for i in range(n_slices):
                if i != n_slices - 1:
                    threads.append(self.start_thread(self._send_file, file, step*i, step, buffer_size,
                                                     ip, port + i, self.current_file_upload_progress))
                else:
                    threads.append(self.start_thread(self._send_file, file, step*i, filesize - step*i, buffer_size,
                                                     ip, port + i, self.current_file_upload_progress))

            for t in threads:
                t.join()

            end_time = round(time.time() - self._send_start_time, 5)
            if end_time == 0:
                end_time = 0.000000000001
            print('Sending time: {} seconds\nSpeed: {} MB/s'.format(
                    end_time, (self._sent_bytes * n_slices / end_time) / (1024 * 1024)))


class SyncFolder2:
    buffers = [b'', b'']
    current_filesize = 0

    def __init__(self, max_ram):
        """
        :param max_ram: maximum ram to use (in MB)
        """
        self.max_ram = int(max_ram * 1024 * 512) # (max_ram * 1024 * 1024) / 2

        self._send_start_time = 0
        self._sent_bytes = 0

        self._opposite_buff = 1

    @staticmethod
    def file_md5(fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    @staticmethod
    def start_thread(target, *args, daemon=False):
        thread = threading.Thread(
                target=target,
                args=args,
                daemon=daemon
        )
        thread.start()
        return thread

    @staticmethod
    def start_process(target, *args, daemon=False):
        process = mp.Process(
                target=target,
                args=args,
                daemon=daemon
        )
        process.start()
        return process

    def send_file(self, filepath, ip, port, buffer_size=-1, socket=None):
        with open(filepath, 'rb', buffering=buffer_size) as file:
            self.current_filesize = os.fstat(file.fileno()).st_size
            print(f"File size: {self.current_filesize} bytes")

            if self.current_filesize < self.max_ram:
                self.max_ram = self.current_filesize
            # localize variable access to minimize overhead
            file_read = file.read

            _bytes = shared_memory.SharedMemory(name='tcp_bytes', create=True, size=self.max_ram)
            tcp_bytes = _bytes.buf[:self.max_ram].cast('B')
            control = shared_memory.SharedMemory(name='control_flags', create=True, size=2)  # tcp, file
            control_flags = control.buf[:2].cast('B')

            # first read
            self.buffers[0] = file_read(self.max_ram)
            tcp_bytes[:self.max_ram] = self.buffers[0]
            # start sending process
            self.start_process(self.tcp_sending, ip, port)
            # try:
            #     self.start_process(self.ws_sending, socket)
            # except TypeError:
            #     self.start_process(self.ws_sending, None)
            #     # pass ssl socket
            #     print(socket)
            #     while tcp_bytes[:2] != b'\00\00':
            #         time.sleep(0.0005)
            #     pid = int.from_bytes(tcp_bytes[:8], "big")
            #     share_bytes = socket.share(pid)
            #     l = len(share_bytes).to_bytes(16, byteorder='big')
            #
            #     tcp_bytes[1:17] = l
            #     tcp_bytes[18:len(share_bytes) + 18] = share_bytes
            #     tcp_bytes[:1] = b'\xff'
            #
            #     socket.close()

            def _read(amount):
                self.buffers[self._opposite_buff] = file_read(amount)

                while control_flags[0] != (control_flags[1] + 1):
                    time.sleep(0.0005)

                tcp_bytes[:amount] = self.buffers[self._opposite_buff]
                self._opposite_buff = self._opposite_buff ^ 1

                if control_flags[0] == 2:
                    control_flags[0] = 0
                    control_flags[1] = 0
                else:
                    control_flags[1] += 1

            r = range(self.max_ram * 2, self.current_filesize, self.max_ram)
            for _ in r:
                _read(self.max_ram)

            try:
                left_bytes = self.current_filesize - r[-1]
            except IndexError: # current_filesize == max_ram
                left_bytes = self.current_filesize - self.max_ram
            if left_bytes:
                _read(left_bytes)

            # tcp_flag, file_flag = self._read_control_values(control_flags)
            while control_flags[0] != (control_flags[1] + 1):
                time.sleep(0.0005)
            if (self.current_filesize % 2) != 0:
                control_flags[1] += 1

            tcp_bytes.release()
            control_flags.release()
            control.unlink()
            _bytes.unlink()

    def tcp_sending(self, ip, port):
        def no_connection():
            print("No connection to server!")
            self._send_start_time = time.time()
            self._sent_bytes = 0

        addr = (ip, port)
        print(addr)
        with sock.socket(sock.AF_INET, sock.SOCK_STREAM, sock.IPPROTO_TCP) as tcp_socket:
            # tcp_socket.settimeout(10)
            # try:
            #     print("connecting...")
            #     tcp_socket.connect(addr)
            # except ConnectionRefusedError:
            #     no_connection()
            #     return
            # except TimeoutError:
            #     no_connection()
            #     return
            print("connecting...")
            tcp_socket.connect(addr)
            print('sending...')

            # sending info
            tcp_socket.sendall(struct.pack('>q', self.max_ram))  # buffer size
            tcp_socket.sendall(struct.pack('>q', self.current_filesize))  # '>q' is long long (8 bytes == 64 bits)

            _bytes = shared_memory.SharedMemory(name='tcp_bytes', size=self.max_ram)
            tcp_bytes = _bytes.buf[:self.max_ram].cast('B')

            control = shared_memory.SharedMemory(name='control_flags', size=2)  # tcp, file
            control_flags = control.buf[:2].cast('B')

            if self.max_ram == self.current_filesize:
                cs = self.current_filesize + 1
            else:
                cs = self.current_filesize
            r = range(self.max_ram, cs, self.max_ram)
            _sent_bytes = 0
            _send_start_time = time.time()

            self.compressed_size = 0
            # c_context = lz4_frame.create_compression_context()
            # comp = lz4_frame.compress_begin(c_context, compression_level=3)
            # cctx = zstd.ZstdCompressor()
            def _send_tcp(amount):
                count = 0
                # tcp_flag, file_flag = self._read_control_values(control_flags)
                while control_flags[0] != control_flags[1]:
                    time.sleep(0.0005)  # 500 microseconds

                # print(self.file_flag.value)
                # print(bytes(tcp_bytes[:]))
                if not tcp_bytes[count:self.max_ram]:
                    return 0

                while count < amount:
                    v = tcp_socket.send(tcp_bytes[count:amount])
                    count += v
                    # print(v)
                # comp = cctx.compress(tcp_bytes[:amount]) # lz4_frame.compress_chunk(c_context, tcp_bytes[:amount])
                # self.compressed_size += len(comp)
                # if len(comp):
                #     print(f"Orig: {amount}, Comp: {len(comp)}, Ratio: {amount / len(comp)}")

                return count

            for _ in r:
                _sent_bytes += _send_tcp(self.max_ram)
                control_flags[0] += 1
                t = time.time() - _send_start_time
                sent = _sent_bytes / 1048576
                print(f'Sending time: {t} seconds ({sent} MB).   Speed: {sent / t} MB/s', end='\r')

            if self.max_ram != self.current_filesize:
                try:
                    last_bytes = self.current_filesize - r[-1]
                    _send_tcp(last_bytes)
                    _sent_bytes += last_bytes
                except ConnectionResetError: # file is fully sent
                    pass
                finally:
                    control_flags[0] += 1

            if (self.current_filesize % 2) != 0:
                time.sleep(0.1)
                control_flags[0] += 1

            t = time.time() - _send_start_time
            # sent = _sent_bytes / 1048576
            # print(f'Sending time: {t} seconds ({sent} MB).  Speed: {sent / t} MB/s')
            # print(f'Sending time: {t}')

            # self.compressed_size += len(lz4_frame.compress_flush(c_context))
            # print(f"Compressed size: {self.compressed_size}, Ratio: {self.current_filesize / self.compressed_size}")

            tcp_bytes.release()
            control_flags.release()

    def ws_sending(self, socket=None):
        _bytes = shared_memory.SharedMemory(name='tcp_bytes', size=self.max_ram)
        tcp_bytes = _bytes.buf[:self.max_ram].cast('B')

        control = shared_memory.SharedMemory(name='control_flags', size=2)  # tcp, file
        control_flags = control.buf[:2].cast('B')

        # share pid
        if socket is None:
            orig_bytes = tcp_bytes[:]

            pid_bytes = os.getpid().to_bytes(8, byteorder='big')
            tcp_bytes[:8] = pid_bytes

            while tcp_bytes[0] != 255:
                time.sleep(0.0005)
            l = int.from_bytes(tcp_bytes[1:17], "big")
            share_bytes = tcp_bytes[18:l + 18]

            s = sock.fromshare(bytes(share_bytes))
            print("ws", len(share_bytes))
            socket = s
            socket = ssl.wrap_socket(s, do_handshake_on_connect=False)
            tcp_bytes = orig_bytes
            print("ws", socket)

        # sending info
        socket.sendall(struct.pack('>q', self.max_ram))  # buffer size
        socket.sendall(struct.pack('>q', self.current_filesize))  # '>q' is long long (8 bytes == 64 bits)

        if self.max_ram == self.current_filesize:
            cs = self.current_filesize + 1
        else:
            cs = self.current_filesize
        r = range(self.max_ram, cs, self.max_ram)
        _sent_bytes = 0
        _send_start_time = time.time()

        # self.compressed_size = 0
        # c_context = lz4_frame.create_compression_context()
        # comp = lz4_frame.compress_begin(c_context, compression_level=3)
        # cctx = zstd.ZstdCompressor()
        def _send_tcp(amount):
            count = 0
            # tcp_flag, file_flag = self._read_control_values(control_flags)
            while control_flags[0] != control_flags[1]:
                time.sleep(0.0005)  # 500 microseconds

            # print(self.file_flag.value)
            # print(bytes(tcp_bytes[:]))
            if not tcp_bytes[count:self.max_ram]:
                return 0

            while count < amount:
                v = socket.send(tcp_bytes[count:amount])
                count += v
                # print(v)
            # comp = cctx.compress(tcp_bytes[:amount]) # lz4_frame.compress_chunk(c_context, tcp_bytes[:amount])
            # self.compressed_size += len(comp)
            # if len(comp):
            #     print(f"Orig: {amount}, Comp: {len(comp)}, Ratio: {amount / len(comp)}")

            return count

        for _ in r:
            _sent_bytes += _send_tcp(self.max_ram)
            control_flags[0] += 1
            t = time.time() - _send_start_time
            sent = _sent_bytes / 1048576
            print(f'Sending time: {t} seconds ({sent} MB).   Speed: {sent / t} MB/s', end='\r')

        if self.max_ram != self.current_filesize:
            try:
                last_bytes = self.current_filesize - r[-1]
                _send_tcp(last_bytes)
                _sent_bytes += last_bytes
            except ConnectionResetError:  # file is fully sent
                pass
            finally:
                control_flags[0] += 1

        if (self.current_filesize % 2) != 0:
            time.sleep(0.1)
            control_flags[0] += 1

        t = time.time() - _send_start_time
        # sent = _sent_bytes / 1048576
        # print(f'Sending time: {t} seconds ({sent} MB).  Speed: {sent / t} MB/s')
        # print(f'Sending time: {t}')

        # self.compressed_size += len(lz4_frame.compress_flush(c_context))
        # print(f"Compressed size: {self.compressed_size}, Ratio: {self.current_filesize / self.compressed_size}")

        tcp_bytes.release()
        control_flags.release()

    def sync_folder(self, ws, socket, root_dir):
        root_dir = root_dir.replace('\\', '/')
        root = root_dir.split('/')[-1]
        for folder_path, _, filenames in os.walk(root_dir):
            while ws.recv() != 'next':
                time.sleep(0.0001)

            folder = folder_path.replace('\\', '/').replace(root_dir, '')[1:]
            folder2 = f"{root}/{folder}"
            ws.send(folder2)
            ws.send(str(len(filenames)))

            for file in filenames:
                while ws.recv() != 'next':
                    time.sleep(0.0001)

                ws.send(file)
                filepath = f"{root_dir}/{folder}/{file}"
                # self.send_file(filepath, None, None, socket=socket)
                self.ws_send_file(filepath, socket)

                print(file, self.file_md5(filepath))

    def ws_send_file(self, filepath, socket):
        # localize variable access to minimize overhead
        tcp_socket_send = socket.send

        _bytes = shared_memory.SharedMemory(name='tcp_bytes', create=True, size=self.max_ram)
        tcp_bytes = _bytes.buf[:self.max_ram].cast('B')
        control = shared_memory.SharedMemory(name='control_flags', create=True, size=2)  # tcp, file
        control_flags = control.buf[:2].cast('B')

        self.start_process(self.ws_reading, filepath)
        # waiting for first read
        while control_flags[0] != 255:
            print('waiting')
            time.sleep(0.0005)
        control_flags[:1] = b'\x00'

        if self.max_ram == self.current_filesize:
            cs = self.current_filesize + 1
        else:
            cs = self.current_filesize
        r = range(self.max_ram, cs, self.max_ram)
        print('filesize', self.current_filesize)
        _sent_bytes = 0
        _send_start_time = time.time()

        def _send_tcp(amount):
            count = 0
            # tcp_flag, file_flag = self._read_control_values(control_flags)
            while control_flags[0] != control_flags[1]:
                time.sleep(0.0005)  # 500 microseconds

            # print(self.file_flag.value)
            # print(bytes(tcp_bytes[:]))
            if not tcp_bytes[count:self.max_ram]:
                return 0

            while count < amount:
                v = tcp_socket_send(tcp_bytes[count:amount])
                count += v
                # print(v

            return count

        for _ in r:
            _sent_bytes += _send_tcp(self.max_ram)
            control_flags[0] += 1
            # t = time.time() - _send_start_time
            # sent = _sent_bytes / 1048576
            # print(f'Sending time: {t} seconds ({sent} MB).   Speed: {sent / t} MB/s', end='\r')

        if self.max_ram != self.current_filesize:
            try:
                last_bytes = self.current_filesize - r[-1]
                _send_tcp(last_bytes)
                _sent_bytes += last_bytes
            except ConnectionResetError:  # file is fully sent
                pass
            finally:
                control_flags[0] += 1

        t = time.time() - _send_start_time
        # sent = _sent_bytes / 1048576
        # print(f'Sending time: {t} seconds ({sent} MB).  Speed: {sent / t} MB/s')
        print(f'Sending time: {t} sec')

        tcp_bytes.release()
        control_flags.release()
        control.unlink()
        _bytes.unlink()

    def ws_reading(self, filepath):
        with open(filepath, 'rb') as file:
            self.current_filesize = os.fstat(file.fileno()).st_size
            if self.current_filesize < self.max_ram:
                self.max_ram = self.current_filesize
            # localize variable access to minimize overhead
            file_read = file.read

            _bytes = shared_memory.SharedMemory(name='tcp_bytes', size=self.max_ram)
            tcp_bytes = _bytes.buf[:self.max_ram].cast('B')

            control = shared_memory.SharedMemory(name='control_flags', size=2)  # tcp, file
            control_flags = control.buf[:2].cast('B')

            # first read
            self.buffers[0] = file_read(self.max_ram)
            tcp_bytes[:self.max_ram] = self.buffers[0]
            control_flags[:1] = b'\xff'

            def _read(amount):
                self.buffers[self._opposite_buff] = file_read(amount)

                while control_flags[0] != (control_flags[1] + 1):
                    time.sleep(0.0005)

                tcp_bytes[:amount] = self.buffers[self._opposite_buff]
                self._opposite_buff = self._opposite_buff ^ 1

                if control_flags[0] == 2:
                    control_flags[0] = 0
                    control_flags[1] = 0
                else:
                    control_flags[1] += 1

            r = range(self.max_ram * 2, self.current_filesize, self.max_ram)
            for _ in r:
                _read(self.max_ram)

            try:
                left_bytes = self.current_filesize - r[-1]
                _read(left_bytes)
            except IndexError:  # current_filesize == max_ram
                pass

            # tcp_flag, file_flag = self._read_control_values(control_flags)
            while control_flags[0] != (control_flags[1] + 1):
                time.sleep(0.0005)

            tcp_bytes.release()
            control_flags.release()

            # control.unlink()
            # _bytes.unlink()

    @staticmethod
    def receive_file(filepath):
        with sock.socket(sock.AF_INET, sock.SOCK_STREAM, sock.IPPROTO_TCP) as tcp_socket:
            tcp_socket.bind(('', 60000))

            tcp_socket.listen(1)
            conn, addr = tcp_socket.accept()
            print('Got connection from', addr)

            # filesize = int(tcp_socket.recv(8))

            with open(filepath, 'wb') as f:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    f.write(data)

            conn.close()


def main():
    sync = SyncFolder()

    sync2 = SyncFolder2(10) # MB
    sync2.send_file(r"D:\Torrents\Microsoft Office 2019 Professional Plus 16.0.12624.20466 (2020.04) (x64)\Microsoft.Office.2016-2019x64.v2020.04.iso", ip='192.168.0.194', port=50000)
    # sync2.receive_file(r'H:\Downloads\de2-70.zip')

    # sync.send_file(r"D:\Torrents\Fallen Doll ver.1.31 [English-Uncen]\1.rar", -1, 1, ip='192.168.0.140', port=50000)

    print('md5:', sync.file_md5(r"D:\Torrents\Microsoft Office 2019 Professional Plus 16.0.12624.20466 (2020.04) (x64)\Microsoft.Office.2016-2019x64.v2020.04.iso"))
    # print('md5:', sync.file_md5(r"H:\Downloads\de2-70.zip"))


if __name__ == '__main__':
    main()
