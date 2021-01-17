import hashlib
import socket as sock
import struct
import threading
from functools import partial
import tqdm
import os


def start_thread(target, *args, daemon=False):
    thread = threading.Thread(
        target=target,
        args=args,
        daemon=daemon
    )
    thread.start()
    return thread


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _open_file(filename, buffer_size):
    # buffer_size = 256  # 1024 * 16
    # filename_size = struct.pack('>i', len(filename))
    # file_size = os.stat(filename).st_size
    with open(filename, 'rb') as file:
        # print(struct.pack('>i', filename_size))
        # tcp_socket.sendall(str.encode(filename))
        #
        # tcp_socket.sendall(struct.pack('>i', file_size))
        parts = list(iter(partial(file.read, buffer_size), b''))
        return parts


def _socket_sendfile(socket, file, offset, count):
    file.seek(offset)
    # blocksize = min(count, 8192) if count else 8192
    blocksize = count
    total_sent = 0
    # localize variable access to minimize overhead
    file_read = file.read
    sock_send = socket.send
    while True:
        # if count:
        blocksize = min(count - total_sent, blocksize)
        if blocksize <= 0:
            break
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
                if sent < len(data):
                    data = data[sent:]
                else:
                    break


def _send_file(file, offset, step_size, buffer_size, ip, port, progress=None):
    addr = (ip, port)
    print(addr)
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM, sock.IPPROTO_TCP) as tcp_socket:
        # tcp_socket.settimeout(10)
        tcp_socket.connect(addr)

        tcp_socket.sendall(struct.pack('>q', step_size)) # long long (8 bytes == 64 bits)
        last_n = 0
        for n in range(buffer_size, step_size, buffer_size):
            _socket_sendfile(tcp_socket, file, offset, n)
            last_n = n
            if progress:
                progress.update(buffer_size)
        _socket_sendfile(tcp_socket, file, offset, step_size - last_n)
        if progress:
            progress.update(step_size - last_n)


def send_file(filename: str, buffer_size: int, n_slices: int, ip: str, port: int):
    filesize = os.path.getsize(filename)
    print(filesize)
    threads = list()
    with open(filename, 'rb') as file:
        step = int(filesize / n_slices) + 1
        print(step)
        progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
        for i in range(n_slices):
            if i != n_slices - 1:
                threads.append(start_thread(_send_file, file, step*i, step, buffer_size, ip, port + i, progress))
            else:
                threads.append(start_thread(_send_file, file, step*i, filesize - step*i, buffer_size,
                                            ip, port + i, progress))

        for t in threads:
            t.join()


def main():
    send_file(r"D:\Torrents\Fallen Doll ver.1.31 [English-Uncen]\FallenDoll(Beta1.31).rar", # FallenDoll(Beta1.31).rar
              buffer_size=1024 * 1024 * 4, n_slices=10, ip='192.168.0.2', port=50000)
    # print(md5(r"D:\Torrents\Fallen Doll ver.1.31 [English-Uncen]\FallenDoll(Beta1.31).rar") ==
    # '850b304de0167be58ee8d0df7d8aa2b8')


if __name__ == '__main__':
    main()
