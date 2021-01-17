import hashlib
import socket as sock
import struct
import threading
from functools import partial
import io
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


def _send_file(parts, i):
    addr = ("192.168.0.2", 50000 + i)
    print(addr)

    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as tcp_socket:
        tcp_socket.settimeout(10)
        tcp_socket.connect(addr)

        n = sum([len(x) for x in parts])
        tcp_socket.send(struct.pack('>q', n)) # long long (8 bytes == 64 bits)
        for block in parts:
            tcp_socket.sendfile()
            tcp_socket.sendall(block)


def send_file(filename: str, buffer_size: int, n_slices: int = 5):
    parts = _open_file(filename, buffer_size)
    l = len(parts)
    step = int(l / n_slices) + 1
    print(sum([len(x) for x in parts]), l, step)
    for i in range(0, l, step):
        start_thread(_send_file, parts[i:i + step], i // step)


def main():
    # send_file(r"D:\Torrents\Fallen Doll ver.1.31 [English-Uncen]\FallenDoll(Beta1.31).rar", buffer_size=1024*16, n_slices=5)
    # send_file(r"D:\Torrents\Fallen Doll ver.1.31 [English-Uncen]\koko.delta", buffer_size=1024 * 16, n_slices=5)
    print(md5(r"D:\Torrents\Fallen Doll ver.1.31 [English-Uncen]\FallenDoll(Beta1.31).rar") == '850b304de0167be58ee8d0df7d8aa2b8')


if __name__ == '__main__':
    main()
