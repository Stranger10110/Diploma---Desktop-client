import hashlib
import os
import struct
#import aiofiles
from time import sleep

import pycurl
import httputils


class FileReader:
    def __init__(self, fp):
        self.fp = fp

    def read_callback(self, size=3_145_728):
        return self.fp.read(size)


class ResponseLine(object):
    """HTTP response line container.
    Attributes:
        version: HTTP version as a float.
        code:    HTTP Response code as an int.
        reason:    HTTP response reason.
    """
    __slots__ = ["version", "code", "reason"]
    def __init__(self, version, code, reason):
        self.version = version
        self.code = code
        self.reason = reason

    def __str__(self):
        return "%s %s" % (self.code, self.reason)

    # evaluates true on good response
    def __nonzero__(self):
        return self.code == 200
    __bool__ = __nonzero__


class Sync:
    @staticmethod
    def file_md5(filename):
        hash_md5 = hashlib.md5()
        with open(filename, "rb") as fi:
            for chunk in iter(lambda: fi.read(16384), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    @staticmethod
    def send_file(tcp_socket, filepath):
        with open(filepath, 'rb') as binf:
            filesize = os.fstat(binf.fileno()).st_size
            tcp_socket.sendall(struct.pack('>q', 8192))
            tcp_socket.sendall(struct.pack('>q', filesize))
            tcp_socket.sendfile(binf)

    @staticmethod
    async def async_file_reader(file_name, buff_size_mb=3_145_728):
        async with aiofiles.open(file_name, 'rb') as f:
            chunk = await f.read(buff_size_mb)
            while chunk:
                yield chunk
                chunk = await f.read(buff_size_mb)

    @staticmethod
    def chunk_file_reader(filepath, buff_size_mb=3_145_728):
        #def gen():
        with open(filepath, 'rb') as f:
            chunk = f.read(buff_size_mb)
            while chunk:
                yield chunk
                chunk = f.read(buff_size_mb)
        #return os.path.getsize(filepath), gen()

    @staticmethod
    def remove_prefix(text, prefix):
        if text.startswith(prefix):
            return text[len(prefix):]
        return text  # or whatever

    # TODO: receive file hash back for confirmation
    def sync_folder(self, root_dir, base_path, ws, tcp_socket):
        root_dir = root_dir.replace('\\', '/')
        root_dir = root_dir[:-1] if root_dir[-1] == '/' else root_dir
        base_path = base_path.replace('\\', '/')

        for dir_path, _, filenames in os.walk(root_dir):
            # while ws.recv() != 'next':
            #     sleep(0.0001)
            if not ws.recv() == 'next':
                return

            # folder_path =
            rel_path = self.remove_prefix(dir_path.replace('\\', '/'), f"{base_path}/")
            ws.send(rel_path)
            ws.send(str(len(filenames)))

            # command = ''
            for fi in filenames:
                # while command != 'next':
                #     command = ws.recv()
                #     sleep(0.0001)
                if not ws.recv() == 'next':
                    return

                ws.send(fi)
                filepath = f"{root_dir}/{fi}"
                self.send_file(tcp_socket, filepath)

                print(fi, self.file_md5(filepath))

    def get_raw_poster(self, url, filepath, headers, header_callback):
        """Initialze a Curl object for a single POST request.
        This sends whatever data you give it, without specifying the content
        type.
        Returns a tuple of initialized Curl and HTTPResponse objects.
        """
        filesize = os.path.getsize(filepath)
        headers.append(f'Content-Length: {str(filesize)}')
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(pycurl.POST, 1)
        c.setopt(c.READFUNCTION, FileReader(open(filepath, 'rb')).read_callback)
        c.setopt(c.POSTFIELDSIZE, filesize)
        c.setopt(pycurl.CUSTOMREQUEST, 'POST')
        c.setopt(c.HEADERFUNCTION, header_callback)
        c.setopt(c.HTTPHEADER, headers)
        self._set_common(url, c)
        return c

    @staticmethod
    def _set_common(url, c):
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        c.setopt(pycurl.AUTOREFERER, 1)
        c.setopt(pycurl.ENCODING, "gzip, deflate")
        c.setopt(pycurl.MAXREDIRS, 255)
        c.setopt(pycurl.CONNECTTIMEOUT, 30)
        c.setopt(pycurl.TIMEOUT, 300)
        c.setopt(pycurl.NOSIGNAL, 1)
        if url[:5] == 'https':
            c.setopt(pycurl.SSLVERSION, 3)
            c.setopt(pycurl.SSL_VERIFYPEER, 0)


# def norm_path(path):
#     path = path[1:].replace('\\', '/')
#     # path = path.split(':')[1:][0][1:]
#     return path


def create_json_from_files(paths):
    result = dict()

    for path in paths:
        path = norm_path(path)

        split = path.split('/')
        dirs = split[:-1]
        file = split[-1]

        for d in dirs.split('/'):
            if result.get(d, None) is None:
                result = list()


# if __name__ == '__main__':
#     s = requests.Session()
#
#     # domain = "https://mgtu-diploma.tk"
#     domain = "c4d0bdc3f23368.localhost.run"
#
#     register = {"username": "test2", "password": "4321", "email": "test2_email"}
#     # r = s.post(f"https://{domain}/api/register", json=register)
#     # print(r.json())
#
#     # confirm = {"username": "test2", 'code': 'leramuradelasotusapo'}
#     # r = s.post(f"https://{domain}/api/confirm_username", json=confirm)
#     # print(r.text)
#
#     r = s.post(f"https://{domain}/api/login", json=register)
#     print(r.text)
#
#     # s.headers['Auth-Expiry'] = r.headers['Auth-Expiry']
#     try:
#         s.headers['X-Auth-Token'] = r.headers['X-Auth-Token']
#         s.headers['X-Refresh-Token'] = r.headers['X-Refresh-Token']
#         s.headers['X-Csrf-Token'] = r.headers['X-Csrf-Token']
#     except Exception:
#         print("jwt error")
#
#     r = s.get(f"https://{domain}/api/restricted_hello")
#     print(r.text)
#
#
#     websocket = create_connection(f"wss://{domain}/api/sync_files", header=dict(s.headers))
#
#     # sync2 = SyncFolder2(10) # MB
#     # sync2.send_file(r"D:\Torrents\Microsoft Office 2019 Professional Plus 16.0.12624.20466 (2020.04) (x64)\Microsoft.Office.2016-2019x64.v2020.04.iso",
#     #                 None, None, socket=conn)
#
#
#     f = r"H:\Downloads\0001-0065.avi"
#
#     files_data = {"filenames": [norm_path(f, r'H:\Downloads')]}
#     json_str = json.dumps(files_data)
#     websocket.send(json_str)
#
#     # send_file(websocket.sock, f, int(10 * 1024 * 512))
#     with open(f, 'rb') as file:
#         websocket.sock.sendfile(file)
#     print(SyncFolder.file_md5(f))
