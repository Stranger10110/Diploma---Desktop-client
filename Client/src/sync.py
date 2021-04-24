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

    def sync_folder_listing(self, api, full_folder_path, base_path):
        base_path = base_path.replace('\\', '/')
        full_folder_path = full_folder_path.replace('\\', '/')
        rel_path = self.remove_prefix(full_folder_path, f'{base_path}/')

        # remote_files = list()
        remote_files = dict()
        r, listing = api.filer_get_folder_listing(rel_path, recursive=True)
        for entry in listing:
            if entry['Mode'] <= 9999:  # is a file
                path = self.remove_prefix(entry['FullPath'], f'/{api.username}/')
                # entry['FullPath_2'] = path
                # remote_files.append(path)
                remote_files[path] = entry

        local_files = set()
        for dir_path, folders, filenames in os.walk(full_folder_path):
            dir_path = dir_path.replace('\\', '/')
            rel_path = self.remove_prefix(dir_path, f'{base_path}/')
            for file in filenames:
                local_files.add(f'{rel_path}/{file}')

        # for test
        t = local_files.pop(6)
        t2 = local_files.pop(9)

        # # #
        local_only = [l for l in local_files if l not in remote_files.keys()]

        remote_only = [r for r in remote_files.keys() if r not in local_files]
        # remote_only_full = [r for path, r in remote_files.items() if path not in local_files]
        remote_only_entries = [remote_files[r] for r in remote_only]

        # contains_both = local_files if len(local_files) <= len(remote_files) else list(remote_files.keys())
        both = [entry for path, entry in remote_files.items() if path not in remote_only + local_only]
        for b in both:
            os.path.getmtime(path)

        #       local paths,            remote entries,      remote entries presented locally
        return (base_path, local_only), remote_only_entries, both

    def sync_file(self):
        pass
