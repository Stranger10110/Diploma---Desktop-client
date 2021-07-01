import atexit
import concurrent
import hashlib
import os
import shutil
import struct
import time
from base64 import b64decode
from concurrent.futures.thread import ThreadPoolExecutor
from errno import ENOENT
from shutil import rmtree
from tempfile import TemporaryDirectory, gettempdir
from threading import Thread
from time import sleep

from src.rdiff import Rdiff


def start_thread(target, *args, **kwargs):
    thread = Thread(
        target=target,
        args=args,
        kwargs=kwargs,
        daemon=True
    )
    thread.start()
    return thread


class CustomResponse:
    def __init__(self, code, text, headers):
        self.status_code = code
        self.text = text
        self.headers = headers


class Sync:
    def __init__(self, api, rsync_dll_path, base_remote_path):
        self.API = api
        self.rdiff = Rdiff(rsync_dll_path)

        if len(base_remote_path) > 0 and base_remote_path[-1] != '/':
            base_remote_path += '/'
        self.base_remote_path = base_remote_path

        self.temp_dir_prefix = 'Seaweed_Cloud_Storage_'
        self.temp_dir = TemporaryDirectory(prefix=self.temp_dir_prefix)
        self.temp_dir.name = self.temp_dir.name.replace('\\', '/')
        atexit.register(self.temp_dir.cleanup)

        self._chunked_md5_full = False
        self.clean_temp_dir()

        self._last_mtimes = dict()
        self._cached_os_walk = dict()
        self._cached_remote_listing = dict()

    @staticmethod
    def is_locked(filepath):
        """Checks if a file is locked by opening it in append mode.
        If no exception thrown, then the file is not locked.
        """
        locked = None
        file_object = None
        try:
            # Opening file in append mode and read the first 8 characters.
            file_object = open(filepath, 'a', buffering=8)
            if file_object:
                locked = False
        except IOError:
            locked = True
        finally:
            if file_object:
                file_object.close()
        return locked

    def wait_for_file_3_times(self, filepath):
        c = 0
        while self.is_locked(filepath) and c <= 3:
            time.sleep(0.7)
            c += 1

        if c >= 3:
            return 0
        return 1

    def wait_for_file_endlessly(self, filepath):
        while self.is_locked(filepath):
            time.sleep(0.7)

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

    def md5_file_generator(self, filepath, size=1_048_576):
        with open(filepath, "rb") as fi:
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

    @staticmethod
    def remove_basepath(path, basepath):
        if len(basepath) - len(path) == 1:
            return ''
        elif path.startswith(basepath):
            return path[len(basepath):]
        return path  # or whatever

    def upload_file(self, filepath, full_remote_path, ws, tcp_socket):
        if ws.recv() != 'next':
            return 0
        ws.send(f'{self.base_remote_path}{full_remote_path}')
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

    @staticmethod
    def _get_first_chunk(remote_meta):
        """ remote_meta['chunks'] are not sorted so we need to do this manually """
        return next((item for item in remote_meta['chunks'] if item.get('offset', None) is None), None)

    @staticmethod
    def _get_local_mtime(path):
        return round(os.path.getmtime(path), 0)

    def sync_folder_listing(self, full_folder_path, base_path, recursive=True):
        base_path = base_path.replace('\\', '/')
        full_folder_path = full_folder_path.replace('\\', '/')
        rel_path = self.remove_basepath(full_folder_path, f'{base_path}/')

        r, listing = self.API.filer_get_folder_listing(rel_path, recursive=recursive)
        if r.status_code >= 300:
            return r, tuple(), list(), list()

        remote_files = dict()
        for entry in listing:
            if entry['Mode'] <= 9999:  # is a file
                rel_path_ = self.remove_prefix(entry['FullPath'], f'/{self.API.username}/')
                remote_files[rel_path_] = entry

        local_files = set()
        for dir_path, folders, filenames in os.walk(full_folder_path):
            dir_path = dir_path.replace('\\', '/')
            rel_path = self.remove_basepath(dir_path, f'{base_path}/')
            if rel_path != '':
                rel_path += '/'
            for file in [x for x in filenames if '~$' not in x]: # filter temp files '~$'
                local_files.add(f'{self.base_remote_path}{rel_path}{file}')
            if not recursive:
                break

        local_only = [self.remove_prefix(l, self.base_remote_path) for l in local_files if l not in remote_files.keys()]
        remote_only = [r for r in remote_files.keys() if r not in local_files]

        both = [(self.remove_prefix(path, self.base_remote_path), entry) for path, entry in remote_files.items()
                if (path not in set(remote_only + local_only))
                and ((self._last_mtimes.get(path, (0, 0))[0] !=
                      self._get_local_mtime(f'{base_path}/{self.remove_prefix(path, self.base_remote_path)}'))
                     or (self._last_mtimes.get(path, (0, 0))[1] != self._get_first_chunk(entry)['mtime']))]
        # if path not in 'only' AND
        # (last_local_mtime != current_local_mtime OR last_remote_mtime != current_remote_mtime)

        # Set last local and remote mtime
        for path, entry in both:
            self._last_mtimes[f'{self.base_remote_path}{path}'] = (
                self._get_local_mtime(f'{base_path}/{path}'),
                self._get_first_chunk(entry)['mtime']
            )

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
        r, sig_path = self.API.filer_download_file(f'{self.base_remote_path}{remote_path}.sig.v',
                                                   self.temp_dir.name, filer_params={'meta': '1'})
        # Делаем дельту
        delta_path = f'{self.temp_dir.name}/{self.base_remote_path}{remote_path}.delta'
        if self.rdiff.delta(sig_path, filepath, delta_path) != 0:
            return 0
        # Загружаем дельту на сервер
        if self.API.ws_upload_new_file_version(delta_path, remote_path, self).status_code != 200:
            return 0
        return 1

    def _sync_both_file_download(self, filepath, remote_path):
        # Делаем сигнатуру локального файла
        sig_path = f'{self.temp_dir.name}/{self.base_remote_path}{remote_path}.sig'
        self.rdiff.signature(filepath, sig_path)
        # Посылаем на сервер сигнатуру и принимаем дельту
        r, delta_path = self.API.ws_download_new_file_version(sig_path, remote_path, self)
        if r.status_code != 200:
            return 0
        # Применяем дельту на локальном файле
        new_filepath = f'{self.temp_dir.name}/{remote_path}_2'
        if not self.wait_for_file_3_times(filepath):
            return 0
        if self.rdiff.patch(filepath, delta_path, new_filepath) != 0:
            return 0
        # Удаляем старый файл и переименовываем новый
        try:
            shutil.move(new_filepath, filepath)
        except PermissionError:
            pass
        return 1

    def sync_both_file(self, filepath, rel_path, remote_meta):
        # self.API._filer_remove_file_md5_tag(rel_path)
        self.API.filer_remove_file_lock(rel_path)

        # Check file lock
        if self.API.filer_get_file_lock(rel_path)[1] not in ('', self.API.client_id):
            return 0

        # Set file lock
        self.API.filer_set_file_lock(rel_path)
        if self.API.filer_get_file_lock(rel_path)[1] != self.API.client_id:
            self.API.filer_remove_file_lock(rel_path)
            return 0

        first_remote_chunk = self._get_first_chunk(remote_meta)
        self.wait_for_file_3_times(filepath)
        file_md5_generator = self.md5_file_generator(filepath, size=first_remote_chunk['size'])

        def chunks_md5s_equals():
            for remote_chunk in sorted(remote_meta['chunks'], key=lambda x: x.get('offset', 0)):
                local_chunk_md5 = next(file_md5_generator)
                remote_chunk_md5 = b64decode(remote_chunk['e_tag'])
                if local_chunk_md5 != remote_chunk_md5:
                    return False
            self._chunked_md5_full = True
            return True

        remote_md5_is_none = remote_meta['Md5'] is None
        file_size = os.path.getsize(filepath)

        # if same sizes AND ((remote_md5 != 'None' AND md5s_equal) OR (remote_md5 == 'None' AND chunk's_md5s_equals))
        if file_size == remote_meta['FileSize'] and \
            ((not remote_md5_is_none and self.md5_whole_file(filepath, bytes_=True) == b64decode(remote_meta['Md5']))
                or (remote_md5_is_none and chunks_md5s_equals())):
            self.API.filer_remove_file_lock(rel_path)
            return 1  # file is already synced

        file_md5_generator.close()

        local_mtime = self._get_local_mtime(filepath)
        remote_mtime = float(str(first_remote_chunk['mtime'])[:10])
        print(f"Синхронизация {filepath}...")
        if local_mtime > remote_mtime:
            if not self._sync_make_version_delta(filepath, rel_path) or not self._sync_both_file_upload(filepath, rel_path):
                return 0
            print('Успешная загрузка!')
        else:
            if not self._sync_both_file_download(filepath, rel_path):
                return 0
            print('Успешное скачивание!')
        return 1

    def sync_folder(self, full_folder_path, base_path, recursive=True, nthreads=10, repeat_time=60, repeat=True, repeat_count=3):
        r, local, remote_only, both = self.sync_folder_listing(full_folder_path, base_path, recursive)
        if r.status_code == 404:
            return self.API.filer_upload_folder(full_folder_path, base_path, recursive=recursive, nthreads=nthreads)
        elif r.status_code >= 300:
            return 0

        base_path, local_only = local
        repeat_list = list()
        futures = list()

        # Upload local_only/download remote_only files
        with ThreadPoolExecutor(nthreads) as pool:
            for l in local_only:
                print(f"Загрузка {base_path}/{l}")
                futures.append(pool.submit(self.API.filer_upload_file_2, f'{base_path}/{l}', base_path))
            for r in remote_only:
                print(f"Скачивание {base_path}/{r}")
                futures.append(pool.submit(self.API.filer_download_file, self.remove_basepath(r, base_path), base_path))
            for _ in concurrent.futures.as_completed(futures):
                pass

        if len(both) > 0:
            def sync_both_files():
                for b in both:
                    rel_path, remote_meta = b  # rel_path == rel_path
                    if not self.sync_both_file(f'{base_path}/{rel_path}', rel_path, remote_meta):
                        repeat_list.append(b)
                    # lock is removed on a server side
        else:
            print()
            return 1

        # TODO: make better repeat
        c = 0
        sync_both_files()
        while len(repeat_list) > 0 and repeat and c <= repeat_count:
            sleep(repeat_time)
            both = repeat_list.copy()
            repeat_list = list()
            sync_both_files()
            c += 1

        print()
        return 1
