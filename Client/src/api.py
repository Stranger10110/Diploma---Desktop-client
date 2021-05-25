import concurrent.futures
import mimetypes
import os
from base64 import b64encode
from concurrent.futures.thread import ThreadPoolExecutor
from json import dumps as json_dumps
from pathlib import Path
from threading import Thread
from time import time as current_time, time, sleep
from urllib.parse import urlencode
from uuid import getnode as uuid_getnode

import requests
from requests_toolbelt import MultipartEncoder
from simplejson.errors import JSONDecodeError
from websocket import create_connection as ws_create_connection, _exceptions as ws_exceptions

from src.sync import Sync


class ThreadWithReturnValue(Thread):
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs=None, daemon=None):
        Thread.__init__(self, group, target, name, args, kwargs, daemon=daemon)
        self._return = None

    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)

    def join(self, *args):
        Thread.join(self, *args)
        return self._return


def start_thread(target, *args, **kwargs):
    thread = ThreadWithReturnValue(
        target=target,
        args=args,
        kwargs=kwargs
    )
    thread.start()
    return thread


class CustomResponse:
    def __init__(self, code, text, headers):
        self.status_code = code
        self.text = text
        self.headers = headers


# decorator
def request2(func):
    def wrapper(self, *args, **kwargs):
        if not self._check_tokens():
            return CustomResponse(0, 'login required', None)

        r = func(self, *args, **kwargs)
        if self.update_tokens_required:
            if isinstance(r, tuple):
                self._update_tokens(r[0])
            else:
                self._update_tokens(r)

        return r

    return wrapper


# decorator
def request(func):
    def wrapper(self, *args, **kwargs):
        r = func(self, *args, **kwargs)
        if isinstance(r, tuple) or isinstance(r, list):
            if r[0] is not None and r[0].headers.get('X-Refresh-Token', None) is not None:
                self.session.headers['X-Csrf-Token'] = r[0].headers['X-Csrf-Token']
        else:
            if r is not None and r.headers.get('X-Refresh-Token', None) is not None:
                self.session.headers['X-Csrf-Token'] = r.headers['X-Csrf-Token']
        return r

    return wrapper


# decorator
def async_request(func):
    async def wrapper(self, *args, **kwargs):
        if not self._check_tokens():
            return CustomResponse(0, 'login required', None)

        r = await func(self, *args, **kwargs)
        if self.update_tokens_required:
            self._update_tokens(r)

        return r

    return wrapper


# TODO: hash password in client ?


class API:
    def __init__(self, host, username, ssl=False):
        bytes_ = (uuid_getnode() + int(time())).to_bytes(8, 'big', signed=False) + bytes(username, encoding='utf-8')
        self.client_id = str(b64encode(bytes_), encoding='utf-8')

        self.host = host
        self.session = requests.Session()

        if ssl:
            self.protocol = 'https'
            self.ws_protocol = 'wss'
        else:
            self.protocol = 'http'
            self.ws_protocol = 'ws'

        self.username = username
        self.auth_expiry = 0
        self.refresh_expiry = 0

        self.refresh_token = None
        self.update_tokens_required = False
        self.login_required = True

    def register(self, username, password, email):
        reg = {"username": username, "password": password, "email": email}
        r = self.session.post(f"{self.protocol}://{self.host}/api/public/register", json=reg)
        return r

    def confirm_user(self, username, code):
        confirm = {"username": username, 'code': code}
        r = self.session.post(f"{self.protocol}://{self.host}/api/public/confirm_username", json=confirm)
        return r

    def login(self, username, password):
        reg = {"username": username, "password": password}
        r = self.session.post(f"{self.protocol}://{self.host}/api/public/login", json=reg)

        if r.status_code == 200 and 'successful' in r.text:
            # self._update_tokens(r)
            # self.update_tokens_required = False
            # self.login_required = False
            self.session.headers['X-Csrf-Token'] = r.headers['X-Csrf-Token']

        return r

    def _update_tokens(self, response):
        headers = response.headers
        if headers is not None:
            if headers.get('X-Refresh-Token', None) is not None:
                self.refresh_token = headers['X-Refresh-Token']
                self.session.headers['X-Auth-Token'] = headers['X-Auth-Token']
                self.session.headers['X-Csrf-Token'] = headers['X-Csrf-Token']

                if self.session.headers.get('X-Refresh-Token', None) is not None:
                    del self.session.headers['X-Refresh-Token']

                self.auth_expiry = int(headers['Auth-Expiry']) - 2
                self.refresh_expiry = int(headers['Refresh-Expiry']) - 2

                if self.session.headers.get('Auth-Expiry', None) is not None:
                    del self.session.headers['Auth-Expiry']

                return
        self.login_required = True

    def _check_tokens(self):
        # return 0 - login is required
        # return 1 - everything is ok

        if self.login_required:
            return 0
        elif current_time() <= self.auth_expiry:
            if self.session.headers.get('X-Auth-Token', None) is None \
                    or self.session.headers.get('X-Csrf-Token', None) is None:
                return 0
            else:
                return 1
        elif self.refresh_token is not None:
            if current_time() <= self.refresh_expiry:
                self.session.headers['X-Refresh-Token'] = self.refresh_token
                self.update_tokens_required = True
                return 1
            else:
                return 0

    def _download_file(self, url, filepath):
        with requests.get(url, stream=True, headers=self.session.headers, cookies=self.session.cookies) as r:
            r.raise_for_status()

            Path(os.path.dirname(filepath)).mkdir(parents=True, exist_ok=True)
            with open(filepath, 'wb') as f:
                for chunk in r.iter_content(chunk_size=None):
                    # If you have chunk encoded response uncomment if
                    # and set chunk_size parameter to None.
                    if chunk:
                        f.write(chunk)
            return CustomResponse(r.status_code, 'Successful download', r.headers)

    @staticmethod
    def _check_filer_folder_path(path):
        if len(path) > 0 and path[-1] != '/':
            path += '/'
        return path

    @staticmethod
    def _check_filer_file_path(path):
        if len(path) > 0 and path[-1] == '/':
            return path[:-1]
        return path

    @staticmethod
    def _norm_paths(*paths):
        return [x.replace('\\', '/') for x in paths]

    def _filer_set_json_header(self, path: str, params: dict):
        json = {'par': params, 'pat': path}
        json_str = json_dumps(json, separators=(',', ':'))
        self.session.headers["Fi-js"] = json_str

    @request
    def hello_word(self):
        r = self.session.get(f"{self.protocol}://{self.host}/api/restricted_hello")
        return r

    def _ws_make_connection(self, url):
        try:
            ws = ws_create_connection(f"{self.ws_protocol}://{self.host}/{url}", header=dict(self.session.headers),
                                      cookie=';'.join([f'{k}={v}' for k, v in self.session.cookies.iteritems()]))
            tcp_socket = ws.sock
        except ws_exceptions.WebSocketBadStatusException as e:
            split = str(e).split()
            code = split[2]
            text = ' '.join(split[3:])

            r = CustomResponse(code, text, None)
            return r, None, False
        return ws, tcp_socket, True

    @request
    def ws_upload_folder(self, root_dir: str, base_path: str, sync_obj: Sync, recursive=True):
        ws, tcp_socket, ok = self._ws_make_connection('api/upload_files')
        if not ok:
            return ws

        sync_obj.upload_folder(root_dir, base_path, ws, tcp_socket, recursive)

        if not ws.recv() == 'next':
            return
        ws.send(r'stop###')
        ws.close()
        r = CustomResponse(200, f'{root_dir} successful', ws.getheaders())
        return r

    @request
    def ws_upload_file(self, filepath, remote_path, sync_obj: Sync):
        ws, tcp_socket, ok = self._ws_make_connection('api/upload_file')
        if not ok:
            return CustomResponse(ws.status, "Could not create ws socket!", ws.headers)

        if sync_obj.upload_file(filepath, remote_path, ws, tcp_socket):
            return CustomResponse(200, f"{filepath} - file uploaded!", ws.headers)
        else:
            return CustomResponse(400, f"Could not upload {filepath}!", ws.headers)

    @request
    def ws_make_version_delta(self, filepath, remote_path, sync_obj: Sync):
        ws, tcp_socket, ok = self._ws_make_connection('api/make_version_delta')
        if not ok:
            return CustomResponse(ws.status, "Could not create ws socket!", ws.headers)

        if sync_obj.upload_file(filepath, remote_path, ws, tcp_socket):
            if ws.recv() == 'stop':
                return CustomResponse(200, f"{filepath} - new file version created!", ws.headers)
            else:
                return CustomResponse(400, f"Could not create new file version (delta) ({remote_path})!", ws.headers)
        else:
            return CustomResponse(400, f"Could not upload {filepath}!", ws.headers)

    @request
    def ws_upload_new_file_version(self, filepath, remote_path, sync_obj: Sync):
        ws, tcp_socket, ok = self._ws_make_connection('api/upload_new_file_version')
        if not ok:
            return CustomResponse(ws.status, "Could not create ws socket!", ws.headers)

        if sync_obj.upload_file(filepath, remote_path, ws, tcp_socket):
            if ws.recv() == 'stop':
                return CustomResponse(200, f"{filepath} - new file version uploaded!", ws.headers)
            else:
                return CustomResponse(400, f"Could not upload new file version ({remote_path})!", ws.headers)
        else:
            return CustomResponse(400, f"Could not upload {filepath}!", ws.headers)

    @request
    def ws_download_new_file_version(self, filepath, remote_path, sync_obj: Sync):
        ws, tcp_socket, ok = self._ws_make_connection('api/download_new_file_version')
        if not ok:
            return CustomResponse(ws.status, "Could not create ws socket!", ws.headers)

        if sync_obj.upload_file(filepath, remote_path, ws, tcp_socket):
            ws.send('next')
            delta_path = f'{sync_obj.temp_dir.name}/{remote_path}.delta'
            sync_obj.receive_file(tcp_socket, delta_path)
            return CustomResponse(200, f"{filepath} - new file version uploaded!", ws.headers), delta_path
        else:
            return CustomResponse(400, f"Could not upload {filepath}!", ws.headers)

    @request
    def share_create_link(self, file: dict):
        r = self.session.put(f"{self.protocol}://{self.host}/api/shared_link", json=file)
        return r

    @request
    def share_remove_link(self, file: dict):
        r = self.session.delete(f"{self.protocol}://{self.host}/api/shared_link", json=file)
        return r

    @request
    def share_download_public_file(self, link, filename):
        url = f"{self.protocol}://{self.host}/share/{link}"
        return self._download_file(url, filename)

    @request
    def share_download_secured_file(self, link, filename):
        url = f"{self.protocol}://{self.host}/secure/share/{link}"
        return self._download_file(url, filename)

    # Filer path: '' == '/username'; 'path' == '/username/path'
    def _get_future_results(self, futures, pool, params, retry=True, count=0):
        if count > 0:
            sleep(5)  # TODO: 2

        results = list()
        retry_list = list()
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            if r.status_code not in (201, 205):
                if isinstance(r, CustomResponse):
                    filepath = r.text
                else:
                    filepath = r.request.body.fields['file'][1].name
                print(f'Failed to upload {filepath}. Retrying ({count + 1})...')
                if count == 5:
                    retry = False
                    break
                retry_list.append(pool.submit(self.filer_upload_file_2, filepath, *params))
            else:
                results.append(r)

        if len(retry_list) > 0 and retry:
            self._get_future_results(retry_list, pool, params, retry=retry, count=count + 1)
        return results

    @request
    def filer_upload_folder(self, full_folder_path: str, base_path: str, filer_params=None, nthreads=10,
                            remote_filename=None, read_size=3_145_728, recursive=True, retry=True):
        if filer_params is None:
            filer_params = dict()
        full_folder_path, base_path = self._norm_paths(full_folder_path, base_path)

        futures = list()
        with ThreadPoolExecutor(nthreads) as pool:
            for dir_path, _, filenames in os.walk(full_folder_path):
                dir_path = dir_path.replace("\\", '/')
                rel_path = Sync.remove_prefix(dir_path, f"{base_path}/")
                for file in filenames:
                    futures.append(pool.submit(self.filer_upload_file,
                                               file, dir_path, rel_path, filer_params, remote_filename, read_size))
                if not recursive:
                    break

            return self._get_future_results(futures, pool, (base_path, filer_params, remote_filename, read_size), retry)

    @request
    # @make_retry(stop=stop_after_attempt(5))
    # @make_retry(stop=stop_after_delay(3)) # TODO: remove or modify retry logic; retry uploading from last uploaded chunk
    def filer_upload_file(self, filename, dir_path, rel_path,
                          filer_params=None, remote_filename=None, read_size=3_145_728):
        if filer_params is None:
            filer_params = dict()
        filepath = f"{dir_path}/{filename}"
        filesize = os.path.getsize(filepath)

        if filesize == 0:
            return CustomResponse(205, "Zero size file", self.session.headers)
        if remote_filename is not None:
            filename = remote_filename
        filename = self._check_filer_file_path(filename)

        mimetype = mimetypes.guess_type(filepath)[0] or '' # TODO: make docx mime shorter
        m = MultipartEncoder(fields={'file': (filename, open(filepath, 'rb'), mimetype)})
        m._read = m.read
        m.read = lambda size: m._read(read_size if filesize >= read_size else filesize)

        headers = self.session.headers.copy()
        headers['Content-Type'] = m.content_type
        headers['Content-Length'] = str(filesize)

        rel_path = self._check_filer_folder_path(rel_path)
        try:
            return requests.post(f"{self.protocol}://{self.host}/api/filer/{rel_path}{filename}?"
                                 f"{urlencode(filer_params)}", data=m, headers=headers, cookies=self.session.cookies,
                                 allow_redirects=True)
        except requests.exceptions.ConnectionError:
            return CustomResponse(400, filepath, {})

    def filer_upload_file_2(self, filepath, base_path, filer_params=None, remote_filename=None, read_size=3_145_728):
        if filer_params is None:
            filer_params = dict()
        filepath, base_path = self._norm_paths(filepath, base_path)

        filename = os.path.basename(filepath) # just file
        dir_path = os.path.dirname(filepath)  # full folder path
        base_path = self._check_filer_file_path(base_path) # remove last slash if exists
        if base_path != dir_path:
            rel_path = Sync.remove_prefix(dir_path, f'{base_path}/') # relative path from cloud root folder
        else:
            rel_path = ''

        return self.filer_upload_file(filename, dir_path, rel_path, filer_params, remote_filename, read_size)

    @request
    def filer_download_file(self, remote_path, local_folder_path, filer_params=None):
        if filer_params is None:
            filer_params = dict()
        url = f"{self.protocol}://{self.host}/api/filer/{self._check_filer_file_path(remote_path)}" \
              f"?{urlencode(filer_params)}"

        filepath = f'{local_folder_path}/{os.path.basename(remote_path)}'
        return self._download_file(url, filepath), filepath

    @request
    def filer_get_folder_listing(self, remote_path: str, recursive: bool, filer_params=None, result=None):
        if result is None:
            result = list()
            self.session.headers["Accept"] = "application/json"

            if filer_params is None:
                filer_params = {}
            elif filer_params.get('namePattern', None) is not None:
                recursive = False
        json_ = {'limit': '100000'} # 'pretty': 'y'
        json_.update(filer_params)

        r = self.session.get(f"{self.protocol}://{self.host}/api/filer/{self._check_filer_file_path(remote_path)}"
                             f"?{urlencode(json_)}")
        if r.status_code >= 300 or r.headers.get('Content-Type', None) != 'application/json':
            recursive = False

        try:
            entries = r.json()['Entries']
            if entries is not None:
                result.extend(entries)
            else:
                return r, result
        except JSONDecodeError:
            return r, result

        if recursive:
            for entry in entries:
                if entry['Mode'] > 9999: # is a folder
                    rpath = Sync.remove_prefix(entry['FullPath'], f'/{self.username}/')
                    self.filer_get_folder_listing(rpath, True, filer_params=filer_params, result=result)
                # else: # is a file
                #     if any(s in entry['FullPath'] for s in filter_keys):
                #     # del entry[i]
            return r, result
        else:
            del self.session.headers["Accept"]
            return r, result

    @request
    def filer_download_folder(self, remote_path: str, local_folder_path: str, recursive: bool, nthreads=10):
        _, listing = self.filer_get_folder_listing(remote_path, recursive)

        futures = list()
        results = list()
        with ThreadPoolExecutor(nthreads) as pool:
            for entry in listing:
                if entry['Mode'] < 9999: # is a file
                    rpath = Sync.remove_prefix(entry['FullPath'], f'/{self.username}/')
                    futures.append(pool.submit(self.filer_download_file,
                                               rpath, f'{local_folder_path}/{"/".join(rpath.split("/")[1:-1])}'))

            for future in concurrent.futures.as_completed(futures):
                results.append(future.result()[0])

        return results

    @request
    def filer_download_zip_folder(self, remote_path, local_folder_path): # recursive by default
        filepath = f'{local_folder_path}/{os.path.basename(remote_path)}.zip'
        url = f"{self.protocol}://{self.host}/api/zip/filer/{self._check_filer_file_path(remote_path)}"
        return self._download_file(url, filepath), filepath

    @request
    def filer_delete_folder(self, remote_path): # recursive by default
        r = self.session.delete(f"{self.protocol}://{self.host}/api/filer/{self._check_filer_folder_path(remote_path)}")
        return r

    @request
    def filer_delete_file(self, remote_path):
        r = self.session.delete(f"{self.protocol}://{self.host}/api/filer/{self._check_filer_file_path(remote_path)}")
        return r

    # TODO: rewrite locks logic (put tag on another file)
    @request
    def filer_set_file_lock(self, remote_path):
        r = self.session.put(f"{self.protocol}://{self.host}/api/filer/{self._check_filer_file_path(remote_path)}"
                             f"?tagging", headers={'Seaweed-Lock': self.client_id})
        return r

    @request
    def filer_get_file_lock(self, remote_path):
        r = self.session.head(f"{self.protocol}://{self.host}/api/filer/{self._check_filer_file_path(remote_path)}"
                              f"?tagging")
        return r, r.headers.get('Seaweed-Lock', '')

    @request
    def filer_remove_file_lock(self, remote_path):
        r = self.session.delete(f"{self.protocol}://{self.host}/api/filer/{self._check_filer_file_path(remote_path)}"
                                f"?tagging=Lock")
        return r

    @request
    def filer_remove_file_tags(self, remote_path, tag_names):
        r = self.session.delete(f"{self.protocol}://{self.host}/api/filer/{self._check_filer_file_path(remote_path)}"
                                f"?tagging={','.join([x.capitalize() for x in tag_names])}")
        return r

    @request
    def filer_set_file_md5_tag(self, remote_path, md5_hash):
        r = self.session.put(f"{self.protocol}://{self.host}/api/filer/{self._check_filer_file_path(remote_path)}"
                             f"?tagging", headers={'Seaweed-md5': md5_hash})
        return r

    @request
    def _filer_remove_file_md5_tag(self, remote_path):
        r = self.session.delete(f"{self.protocol}://{self.host}/api/filer/{self._check_filer_file_path(remote_path)}"
                                f"?tagging=Md5")
        return r

    @request
    def version_list(self, remote_path):
        r = self.session.get(f"{self.protocol}://{self.host}/api/version/{self._check_filer_file_path(remote_path)}")
        return r

    @request
    def version_downgrade(self, version, remote_path):
        r = self.session.patch(f"{self.protocol}://{self.host}/api/version",
                               json={'version': version, 'rel_path': self._check_filer_file_path(remote_path)})
        return r

    @request
    def admin_set_group_for_user(self, user, group):
        return self.session.put(f"{self.protocol}://{self.host}/api/admin/users/group",
                                json={'username': user, 'group': group})

    @request
    def admin_remove_group_from_user(self, user, group):
        return self.session.delete(f"{self.protocol}://{self.host}/api/admin/users/group",
                                   json={'username': user, 'group': group})
