import hashlib
import os
import struct

from src.rdiff import Rdiff


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
    def chunk_file_reader(filepath, buff_size_mb=3_145_728):
        with open(filepath, 'rb') as f:
            chunk = f.read(buff_size_mb)
            while chunk:
                yield chunk
                chunk = f.read(buff_size_mb)

    @staticmethod
    def remove_prefix(text, prefix):
        if text.startswith(prefix):
            return text[len(prefix):]
        return text  # or whatever

    def upload_folder(self, root_dir, base_path, ws, tcp_socket, recursive=True):
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
                filepath = f"{dir_path}/{fi}"
                self.send_file(tcp_socket, filepath)

                print(fi, self.file_md5(filepath))

            if not recursive:
                break

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


        local_files = set()
        for dir_path, folders, filenames in os.walk(full_folder_path):
            dir_path = dir_path.replace('\\', '/')
            rel_path = self.remove_prefix(dir_path, f'{base_path}/')
            for file in filenames:
                local_files.add(f'{rel_path}/{file}')


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
