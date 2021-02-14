import hashlib
import os
import socket as sock
import struct
import sys
import threading
import time

from multiprocessing import shared_memory, Lock
import multiprocessing as mp
from threading import Lock

s_print_lock = Lock()
# import tqdm


def s_print(*a, **b):
    """Thread safe print function"""
    with s_print_lock:
        print(*a, **b)


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
                # self._sent_bytes = tcp_socket.sendfile(file, offset, step_size)
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
            self.current_file_upload_progress = None# tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B",
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

    def send_file(self, filepath, ip, port, buffer_size=-1):
        with open(filepath, 'rb', buffering=buffer_size) as file:
            self.current_filesize = os.fstat(file.fileno()).st_size
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
            self.start_process(self.tcp_sending, ip, port)

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
            except IndexError: # current_filesize == max_ram
                pass

            # tcp_flag, file_flag = self._read_control_values(control_flags)
            while control_flags[0] != (control_flags[1] + 1):
                time.sleep(0.0005)

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
            try:
                print("connecting...")
                tcp_socket.connect(addr)
            except ConnectionRefusedError:
                no_connection()
                return
            except TimeoutError:
                no_connection()
                return
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

                return count

            for _ in r:
                _sent_bytes += _send_tcp(self.max_ram)
                control_flags[0] += 1
                t = time.time() - _send_start_time
                sent = _sent_bytes / 1048576
                print(f'Sending time: {t} seconds ({sent} MB).   Speed: {sent / t} MB/s', end='\r')

            if not (self.max_ram == self.current_filesize):
                try:
                    last_bytes = self.current_filesize - r[-1]
                    _send_tcp(last_bytes)
                    _sent_bytes += last_bytes
                except ConnectionResetError: # file is fully sent
                    pass
                finally:
                    control_flags[0] += 1

            t = time.time() - _send_start_time
            sent = _sent_bytes / 1048576
            print(f'Sending time: {t} seconds ({sent} MB).  Speed: {sent / t} MB/s')

            tcp_bytes.release()
            control_flags.release()
            control.unlink()
            _bytes.unlink()


def main():
    sync = SyncFolder()

    sync2 = SyncFolder2(15) # MB
    sync2.send_file(r"D:\Torrents\Fallen Doll ver.1.31 [English-Uncen]\1.rar", ip='192.168.0.140', port=50000)

    # sync.send_file(r"D:\Torrents\Fallen Doll ver.1.31 [English-Uncen]\1.rar", -1, 1, ip='192.168.0.140', port=50000)

    print('md5:', sync.file_md5(r"D:\Torrents\Fallen Doll ver.1.31 [English-Uncen]\1.rar"))


if __name__ == '__main__':
    main()
