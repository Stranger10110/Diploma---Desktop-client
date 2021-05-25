import atexit
import concurrent
import hashlib
import os
import shutil
import struct
from base64 import b64decode
from concurrent.futures.thread import ThreadPoolExecutor
from errno import ENOENT
from shutil import rmtree
from tempfile import TemporaryDirectory, gettempdir
from time import sleep

from src.rdiff import Rdiff


class CustomResponse:
    def __init__(self, code, text, headers):
        self.status_code = code
        self.text = text
        self.headers = headers


class Sync:
    def __init__(self, api, rsync_dll_path):
        self.API = api
        self.rdiff = Rdiff(rsync_dll_path)

        self.temp_dir_prefix = 'Seaweed_Cloud_Storage_'
        self.temp_dir = TemporaryDirectory(prefix=self.temp_dir_prefix)
        self.temp_dir.name = self.temp_dir.name.replace('\\', '/')
        atexit.register(self.temp_dir.cleanup)

        self._chunked_md5_full = False
        self.clean_temp_dir()

    @staticmethod
    def silent_remove(filename):
        try:
            os.remove(filename)
        except OSError as e:
            if e.errno != ENOENT:  # errno.ENOENT = no such file or directory
                raise  # re-raise exception if a different error occurred

    def clean_temp_dir(self):
        dir_path, folders, _ = next(os.walk(gettempdir()))
        for folder in folders:
            if self.temp_dir_prefix in folder and os.path.basename(self.temp_dir.name) not in folder:
                rmtree(os.path.join(dir_path, folder))

    @staticmethod
    def md5_whole_file(filename, bytes_=False):
        hash_md5 = hashlib.md5()
        with open(filename, "rb") as fi:
            for chunk in iter(lambda: fi.read(16384), b""):
                hash_md5.update(chunk)

        if not bytes_:
            return hash_md5.hexdigest()
        else:
            return hash_md5.digest()

    @staticmethod
    def md5_file_generator(filename, size=1_048_576):
        with open(filename, "rb") as fi:
            fsize = os.fstat(fi.fileno()).st_size
            if fsize < size:
                size = fsize

            # whole_md5 = hashlib.md5()
            for chunk in iter(lambda: fi.read(size), b""):
                # whole_md5.update(chunk)
                # # #
                chunked_md5 = hashlib.md5(chunk)
                yield chunked_md5.digest()
            # yield whole_md5.digest()

    @staticmethod
    def send_file(tcp_socket, filepath):
        with open(filepath, 'rb') as binf:
            filesize = os.fstat(binf.fileno()).st_size
            tcp_socket.sendall(struct.pack('>q', 8192))
            tcp_socket.sendall(struct.pack('>q', filesize))
            tcp_socket.sendfile(binf)

    @staticmethod
    def receive_file(tcp_socket, filepath, filemode='wb', buff_size=16384):
        with open(filepath, filemode) as file:
            while 1:
                buf = tcp_socket.recv(buff_size)
                if not buf or buf == b'stop':
                    break
                file.write(buf)

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

    def upload_file(self, filepath, full_remote_path, ws, tcp_socket):
        if ws.recv() != 'next':
            return 0
        ws.send(full_remote_path)
        self.send_file(tcp_socket, filepath)

        if ws.recv() == 'stop':
            return 1
        else:
            return 0

    def upload_folder(self, root_dir, base_path, ws, tcp_socket, recursive=True):
        root_dir = root_dir.replace('\\', '/')
        root_dir = root_dir[:-1] if root_dir[-1] == '/' else root_dir
        base_path = base_path.replace('\\', '/')

        for dir_path, _, filenames in os.walk(root_dir):
            if ws.recv() != 'next':
                return

            rel_path = self.remove_prefix(dir_path.replace('\\', '/'), f"{base_path}/")
            ws.send(rel_path)
            ws.send(str(len(filenames)))

            for fi in filenames:
                if ws.recv() != 'next':
                    return

                ws.send(fi)
                filepath = f"{dir_path}/{fi}"
                self.send_file(tcp_socket, filepath)

                # print(fi, self.file_md5(filepath))

            if not recursive:
                break

    def sync_folder_listing(self, full_folder_path, base_path, recursive=True):
        base_path = base_path.replace('\\', '/')
        full_folder_path = full_folder_path.replace('\\', '/')
        rel_path = self.remove_prefix(full_folder_path, f'{base_path}/')

        remote_files = dict()
        r, listing = self.API.filer_get_folder_listing(rel_path, recursive=recursive)
        if r.status_code >= 300:
            return r, tuple(), list(), list()
        for entry in listing:
            if entry['Mode'] <= 9999:  # is a file
                rel_path = self.remove_prefix(entry['FullPath'], f'/{self.API.username}/')
                remote_files[rel_path] = entry

        local_files = set()
        for dir_path, folders, filenames in os.walk(full_folder_path):
            dir_path = dir_path.replace('\\', '/')
            rel_path = self.remove_prefix(dir_path, f'{base_path}/')
            for file in filenames:
                local_files.add(f'{rel_path}/{file}')
            if not recursive:
                break

        local_only = [l for l in local_files if l not in remote_files.keys()]
        remote_only = [r for r in remote_files.keys() if r not in local_files]
        # remote_only_entries = [(r, remote_files[r]) for r in remote_only]
        both = [(path, entry) for path, entry in remote_files.items() if path not in set(remote_only + local_only)]

        #      response, local paths,             remote paths, remote entries presented locally
        return r,        (base_path, local_only), remote_only,  both

    def _sync_make_version_delta(self, filepath, rel_path):
        sig_path = f'{self.temp_dir.name}/{rel_path}.sig'
        res = self.rdiff.signature(filepath, sig_path)
        if res != 0:
            return 0 # CustomResponse(400, "Could not create signature!", dict())
        if self.API.ws_make_version_delta(sig_path, rel_path, self).status_code != 200:
            return 0
        return 1

    def _sync_both_file_upload(self, filepath, remote_path):
        # Принимаем сигнатуру
        r, sig_path = self.API.filer_download_file(f'{remote_path}.sig.v', self.temp_dir.name, filer_params={'meta': '1'})
        # Делаем дельту
        delta_path = f'{self.temp_dir.name}/{remote_path}.delta'
        if self.rdiff.delta(sig_path, filepath, delta_path) != 0:
            return 0
        # Загружаем дельту на сервер
        if self.API.ws_upload_new_file_version(delta_path, remote_path, self).status_code != 200:
            return 0
        return 1

    def _sync_both_file_download(self, filepath, remote_path):
        # Делаем сигнатуру локального файла
        sig_path = f'{self.temp_dir.name}/{remote_path}.sig'
        self.rdiff.signature(filepath, sig_path)
        # Посылаем на сервер сигнатуру и принимаем дельту
        r, delta_path = self.API.ws_download_new_file_version(sig_path, remote_path, self)
        if r.status_code != 200:
            return 0
        # Применяем дельту на локальном файле
        new_filepath = f'{self.temp_dir.name}/{remote_path}_2'
        if self.rdiff.patch(filepath, delta_path, new_filepath) != 0:
            return 0
        # Удаляем старый файл и переименовываем новый
        shutil.move(new_filepath, filepath)
        return 1

    def sync_both_file(self, filepath, remote_path, remote_meta):
        # self.API._filer_remove_file_md5_tag(remote_path)
        # self.API.filer_remove_file_lock(remote_path)

        # Check file lock
        if self.API.filer_get_file_lock(remote_path)[1] not in ('', self.API.client_id):
            return 0

        # Set file lock
        self.API.filer_set_file_lock(remote_path)
        if self.API.filer_get_file_lock(remote_path)[1] != self.API.client_id:
            self.API.filer_remove_file_lock(remote_path)
            return 0

        file_md5_generator = self.md5_file_generator(
            filepath, size=next((item['size'] for item in remote_meta['chunks'] if item.get('offset', None) is None), None)
        )

        def chunks_md5s_equals():
            for remote_chunk in sorted(remote_meta['chunks'], key=lambda x: x.get('offset', 0)):
                local_chunk_md5 = next(file_md5_generator)
                remote_chunk_md5 = b64decode(remote_chunk['e_tag'])
                if local_chunk_md5 != remote_chunk_md5:
                    return False
            self._chunked_md5_full = True
            return True

        remote_md5_is_none = remote_meta['Md5'] is None
        # if remote_md5_is_none:
        #     if remote_meta['Extended'] is not None and remote_meta['Extended'].get('Seaweed-Md5', None) is not None:
        #         remote_meta['Md5'] = remote_meta['Extended']['Seaweed-Md5']
        #         remote_md5_is_none = False
        file_size = os.path.getsize(filepath)

        # def update_remote_md5():
        #     if remote_md5_is_none:
        #         if self._chunked_md5_full:
        #             md5 = b64encode(next(file_md5_generator)).decode(encoding='utf-8')
        #         else:
        #             md5 = b64encode(self.md5_whole_file(filepath, bytes_=True)).decode(encoding='utf-8')
        #         self.API.filer_set_file_md5_tag(remote_path, md5)
        #         self._chunked_md5_full = False

        # if same sizes AND ((remote_md5 != 'None' AND md5s_equal) OR (remote_md5 == 'None' AND chunk's_md5s_equals))
        if file_size == remote_meta['FileSize'] and \
            ((not remote_md5_is_none and self.md5_whole_file(filepath, bytes_=True) == b64decode(remote_meta['Md5']))
                or (remote_md5_is_none and chunks_md5s_equals())):
            self.API.filer_remove_file_lock(remote_path)
            # update_remote_md5()
            return 1  # file is already synced

        # update_remote_md5()
        file_md5_generator.close()

        local_mtime = round(os.path.getmtime(filepath), 0)
        remote_mtime = float(str(remote_meta['chunks'][0]['mtime'])[:10])
        if local_mtime > remote_mtime + 0.0:  # local_mtime >> remote_mtime // TODO: + 50.0 (temp)
            if not self._sync_make_version_delta(filepath, remote_path) or not self._sync_both_file_upload(filepath, remote_path):
                return 0
            print('Success upload!')
        else:
            if not self._sync_both_file_download(filepath, remote_path):
                return 0
            print('Success download!')
        return 1

    def sync_folder(self, full_folder_path, base_path, recursive=True, nthreads=10, repeat_time=2): # TODO: 2 = 60 (temp)
        r, local, remote_only, both = self.sync_folder_listing(full_folder_path, base_path, recursive)
        if r.status_code == 404:
            return self.API.filer_upload_folder(full_folder_path, base_path, recursive=recursive, nthreads=nthreads)
        elif r.status_code >= 300:
            return 0

        base_path, local_only = local
        repeat = list()
        futures = list()

        # Upload local_only/download remote_only files
        with ThreadPoolExecutor(nthreads) as pool:
            for l in local_only:
                futures.append(pool.submit(self.API.filer_upload_file_2, f'{base_path}/{l}', base_path))
            for r in remote_only:
                futures.append(pool.submit(self.API.filer_download_file, r, base_path))
            for _ in concurrent.futures.as_completed(futures):
                pass

            if len(both) > 0:
                def sync_both_files():
                    for b in both:
                        remote_path, remote_meta = b  # remote_path == rel_path
                        if not self.sync_both_file(f'{base_path}/{remote_path}', remote_path, remote_meta):
                            repeat.append(b)
                        # lock is removed on a server side
            else:
                return 1

            # def sync_both_files():
            #     for b in both:
            #         remote_path, remote_meta = b  # remote_path == rel_path
            #         futures.append(pool.submit(self.sync_both_file, f'{base_path}/{remote_path}', remote_path, remote_meta))
            #
            #     for future in concurrent.futures.as_completed(futures):
            #         if not future.result():
            #             repeat.append()

            # TODO: make better repeat
            sync_both_files()
            while len(repeat) > 0:
                sleep(repeat_time)
                both = repeat.copy()
                print(both)
                sync_both_files()

        return 1
