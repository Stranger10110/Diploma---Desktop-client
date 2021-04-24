from base64 import b64encode
import concurrent.futures
import mimetypes
import os
from uuid import getnode as uuid_getnode
from concurrent.futures.thread import ThreadPoolExecutor
from json import dumps as json_dumps
from pathlib import Path
from pprint import pprint
from threading import Thread
from time import time as current_time, sleep, time

import magic
import requests
from requests_toolbelt import MultipartEncoder
from simplejson.errors import JSONDecodeError
from tenacity import retry, stop_after_attempt

from src.sync import Sync

mime = magic.Magic(mime=True)

from websocket import create_connection as ws_create_connection, _exceptions as ws_exceptions


def start_thread(target, *args, **kwargs):
    thread = Thread(
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
def request(func):
    def wrapper(self, *args, **kwargs):
        if not self.check_tokens():
            return CustomResponse(0, 'login required', None)

        r = func(self, *args, **kwargs)
        if self.update_tokens_required:
            if isinstance(r, tuple):
                self.update_tokens(r[0])
            else:
                self.update_tokens(r)

        return r

    return wrapper


# decorator
def async_request(func):
    async def wrapper(self, *args, **kwargs):
        if not self.check_tokens():
            return CustomResponse(0, 'login required', None)

        r = await func(self, *args, **kwargs)
        if self.update_tokens_required:
            self.update_tokens(r)

        return r

    return wrapper


# TODO: hash password in client ?


class API:
    def __init__(self, host, username, ssl=False):
        bytes_ = (uuid_getnode() + int(time())).to_bytes(8, 'big', signed=False) + bytes(username, encoding='utf-8')
        self.client_id = str(b64encode(bytes_), encoding='utf-8')

        self.host = host
        # self.async_client = httpclient.AsyncHTTPClient()
        # self.curl_headers = dict()
        self.session = requests.Session()

        if ssl:
            self.protocol = 'https'
        else:
            self.protocol = 'http'

        self.username = username
        self.auth_expiry = 0
        self.refresh_expiry = 0

        self.refresh_token = None
        self.update_tokens_required = False
        self.login_required = True

    def register(self, username, password, email):
        reg = {"username": username, "password": password, "email": email}
        r = self.session.post(f"{self.protocol}://{self.host}/api/register", json=reg)
        return r

    def confirm_user(self, username, code):
        confirm = {"username": username, 'code': code}
        r = self.session.post(f"{self.protocol}://{self.host}/api/confirm_username", json=confirm)
        return r

    def login(self, username, password):
        reg = {"username": username, "password": password}
        r = self.session.post(f"{self.protocol}://{self.host}/api/login", json=reg)

        if r.status_code == 200 and 'successful' in r.text:
            self.update_tokens(r)
            self.update_tokens_required = False
            self.login_required = False

        return r

    def update_tokens(self, response):
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

    def check_tokens(self):
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

    @staticmethod
    def download_file(url, filepath, headers):
        with requests.get(url, stream=True, headers=headers) as r:
            r.raise_for_status()

            Path(os.path.dirname(filepath)).mkdir(parents=True, exist_ok=True)
            with open(filepath, 'wb') as f:
                for chunk in r.iter_content(chunk_size=3_145_728):  # 3 MB
                    # If you have chunk encoded response uncomment if
                    # and set chunk_size parameter to None.
                    # if chunk:
                    f.write(chunk)
            return CustomResponse(r.status_code, 'Successful download', r.headers)

    @staticmethod
    def check_filer_folder_path(path):
        if len(path) > 0 and path[-1] != '/':
            path += '/'
        return path

    @staticmethod
    def check_filer_file_path(path):
        if len(path) > 0 and path[-1] == '/':
            return path[:-1]
        return path

    @staticmethod
    def norm_paths(*paths):
        return [x.replace('\\', '/') for x in paths]

    def filer_set_json_header(self, path: str, params: dict):
        json = {'par': params, 'pat': path}
        json_str = json_dumps(json, separators=(',', ':'))
        self.session.headers["Fi-js"] = json_str

    def remove_upload_headers(self):
        del self.session.headers['Content-Length']
        del self.session.headers['Content-Md5']
        del self.session.headers['Content-Type']

    @request
    def hello_word(self):
        r = self.session.get(f"{self.protocol}://{self.host}/api/restricted_hello")
        return r

    @request
    def ws_upload_folder(self, root_dir: str, base_path: str, recursive=True):
        try:
            # TODO: set wss (TLS)
            ws = ws_create_connection(f"ws://{self.host}/api/upload_files", header=dict(self.session.headers))
            tcp_socket = ws.sock
        except ws_exceptions.WebSocketBadStatusException as e:
            split = str(e).split()
            code = split[2]
            text = ' '.join(split[3:])

            r = CustomResponse(code, text, None)
            return r

        sync = Sync()
        sync.upload_folder(root_dir, base_path, ws, tcp_socket, recursive)

        while ws.recv() != 'next':
            sleep(0.0001)
        ws.send(r'stop###')
        ws.close()
        r = CustomResponse(200, f'{root_dir} successful', ws.getheaders())
        return r

    @request
    def create_shared_link(self, file: dict):
        r = self.session.get(f"{self.protocol}://{self.host}/api/shared_link", json=file)
        return r

    @request
    def delete_shared_link(self, file: dict):
        r = self.session.delete(f"{self.protocol}://{self.host}/api/shared_link", json=file)
        return r

    @request
    def download_public_shared_file(self, link, filename):
        url = f"{self.protocol}://{self.host}/public_share/{link}"
        return self.download_file(url, filename)

    @request
    def download_secured_shared_file(self, link, filename):
        url = f"{self.protocol}://{self.host}/secure_share/{link}"
        return self.download_file(url, filename)

    # Filer path: '' == /username; 'path' == /username/path

    # TODO: add retry uploading from last uploaded chunk
    @request
    def filer_upload_folder(self, full_folder_path: str, base_path: str, filer_params: dict, nthreads=10,
                            remote_filename=None, read_size=3_145_728, recursive=True):
        # full_folder_path = full_folder_path.replace("\\", '/')
        # base_path = base_path.replace("\\", '/')
        full_folder_path, base_path = self.norm_paths(full_folder_path, base_path)

        futures = list()
        results = list()
        with ThreadPoolExecutor(nthreads) as pool:
            for dir_path, _, filenames in os.walk(full_folder_path):
                dir_path = dir_path.replace("\\", '/')
                rel_path = Sync.remove_prefix(dir_path, f"{base_path}/")
                for file in filenames:
                    futures.append(pool.submit(self.filer_upload_file,
                                               file, dir_path, rel_path, filer_params, remote_filename, read_size))
                if not recursive:
                    break

            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        self.remove_upload_headers()
        return results

    @retry(stop=stop_after_attempt(3)) # TODO: remove or modify retry logic
    def filer_upload_file(self, filename, dir_path, rel_path, filer_params, remote_filename=None, read_size=3_145_728):
        filepath = f"{dir_path}/{filename}"
        filesize = os.path.getsize(filepath)
        if filesize == 0:
            return CustomResponse(205, "Zero size file", self.session.headers)

        if remote_filename is not None:
            filename = remote_filename

        mimetype = mimetypes.guess_type(filepath)[0] or ''
        m = MultipartEncoder(fields={'f': (None, open(filepath, 'rb'), mimetype)})
        m._read = m.read
        m.read = lambda size: m._read(read_size if filesize >= read_size else filesize)

        if rel_path != '':
            rel_path += '/'
        self.filer_set_json_header(f"{rel_path}{filename}", filer_params)
        headers = self.session.headers.copy()
        headers['Content-Type'] = m.content_type
        headers['Content-Length'] = str(filesize)

        r = requests.post(f"{self.protocol}://{self.host}/api/filer", data=m, headers=headers, allow_redirects=True)
        self.session.headers = r.headers

        return r

    def filer_upload_file_2(self, filepath, base_path, filer_params, remote_filename=None, read_size=3_145_728):
        filepath, base_path = self.norm_paths(filepath, base_path)

        filename = os.path.basename(filepath) # just file
        dir_path = filepath.replace(f'/{filename}', '') # full folder path
        base_path = self.check_filer_file_path(base_path) # remove last slash if exists
        if base_path != dir_path:
            rel_path = Sync.remove_prefix(dir_path, f'{base_path}/') # relative path from cloud root folder
        else:
            rel_path = ''

        self.filer_upload_file(filename, dir_path, rel_path, filer_params, remote_filename, read_size)

    @request
    def filer_download_file(self, remote_path, local_folder_path):
        self.filer_set_json_header(self.check_filer_file_path(remote_path), {})
        url = f"{self.protocol}://{self.host}/api/filer"
        return self.download_file(url, f'{local_folder_path}/{remote_path}', self.session.headers)

    @request
    def filer_get_folder_listing(self, remote_path: str, recursive: bool, filer_params=None, result=None):
        if result is None:
            result = list()
            self.session.headers["Accept"] = "application/json"

            if filer_params is None:
                filer_params = {}
        json_ = {'limit': '50000'} # 'pretty': 'y'
        json_.update(filer_params)
        self.filer_set_json_header(self.check_filer_folder_path(remote_path), json_)

        r = self.session.get(f"{self.protocol}://{self.host}/api/filer")
        if r.status_code >= 300 or r.headers['Content-Type'] != 'application/json':
            recursive = False

        try:
            entries = r.json()['Entries']
            result.extend(entries)
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
                    futures.append(pool.submit(self.filer_download_file, rpath, local_folder_path))

            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        return results

    @request
    def filer_delete_folder(self, remote_path): # recursive by default
        self.filer_set_json_header(self.check_filer_folder_path(remote_path), {})
        r = self.session.delete(f"{self.protocol}://{self.host}/api/filer")
        return r

    @request
    def filer_set_file_lock(self, remote_path):
        self.filer_set_json_header(self.check_filer_file_path(remote_path), {'tagging': ''})
        r = self.session.put(f"{self.protocol}://{self.host}/api/filer", headers={'Seaweed-lock': self.client_id})
        return r

    @request
    def filer_get_file_lock(self, remote_path):
        self.filer_set_json_header(self.check_filer_file_path(remote_path), {'tagging': ''})
        r = self.session.head(f"{self.protocol}://{self.host}/api/filer")
        return r, r.headers.get('Seaweed-lock', '')

    @request
    def filer_remove_file_lock(self, remote_path):
        self.filer_set_json_header(self.check_filer_file_path(remote_path), {'tagging': ''})
        r = self.session.delete(f"{self.protocol}://{self.host}/api/filer")
        return r


def test(api):
    api.filer_delete_folder("Platform_designer_lab")
    start_time = time()
    api.ws_upload_folder(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab",
                         r"C:\Content\VUS\Efremov\TA\3_4_kurs", recursive=True)
    print("\n\n--- Run time: %s seconds ---\n\n" % (round(time() - start_time, 5)))

    api.filer_delete_folder("Platform_designer_lab")
    start_time = time()
    api.filer_upload_folder(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab",
                            r"C:\Content\VUS\Efremov\TA\3_4_kurs", {}, recursive=True)
    print("\n\n--- Run time: %s seconds ---\n\n" % (round(time() - start_time, 5)))


def test_locks(api, remote_path):
    api.filer_set_file_lock(remote_path)
    _, lock = api.filer_get_file_lock(remote_path)
    print(lock)
    api.filer_remove_file_lock(remote_path)


def main():
    # print(Sync.file_md5(r"H:\Downloads\KINGSTON\KINGSTON\Quartus_Desktop\MILI\MILI_Scheme.bdf"))
    user = {"username": "test2", "password": "4321", "email": "test2_email"}
    host = "192.168.0.2:8080"
    # api = API("mgtu-diploma.tk", user['username'])
    api = API(host, user['username'], ssl=False)
    sync = Sync()

    # print(api.register(*user.values()).text)
    # print(api.confirm_user(user['username'], 'ebioovumogubigefumab').text)
    # return

    r = api.login(user['username'], user['password'])
    if r.status_code != 200:
        print(f"Can't login {r.status_code} {r.text}")
        return

    # print(api.hello_word().text)

    # print(api.download_public_shared_file("253c5bbe220c9bc39e630b4ec61670fca", r"C:\Users\Nikita\Desktop\VHDL.pptx"))

    # test(api)
    # pprint(sync.sync_folder_listing(api, r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab",
    #                                 r"C:\Content\VUS\Efremov\TA\3_4_kurs"))
    test_locks(api, 'Platform_designer_lab/Platform_designer_lab.pdf')

    # print(api.filer_upload_file_2(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab\test.pdf",
    #                               r"C:\Content\VUS\Efremov\TA\3_4_kurs", {'op': 'append'},
    #                               remote_filename='Platform_designer_lab.pdf'))
    # print(api.filer_upload_file_2(r"C:\Content\VUS\Diploma\GUI\test_data\hello.docx",
    #                               r"C:\Content\VUS\Diploma\GUI\test_data", {}))

    # print(api.filer_download_file('Platform_designer_lab/Platform_designer_lab.pdf', '..').text)

    # api.filer_download_folder('', '..', recursive=True)

    #     # file1 = r"H:\Downloads\KINGSTON\KINGSTON\Quartus_Desktop\MILI\MILI_Scheme.bdf"
    #     # print(api.sync_files(folder1).text)
    #
    #     # 253c5bbe220c9bc39e630b4ec61670fca
    #     file1 = {'path': 'Quartus_Desktop/VHDL.pptx', 'exp_time': '0', 'type': 'pub',
    #              'link_hash': '253c5bbe220c9bc39e630b4ec61670fca'}
    #
    #     # 1c55bed5427e543a5444a000ab2f9f5ab
    #     file2 = {'path': 'MILI/cache.zip', 'exp_time': '0', 'type': 'grp_test_group',
    #              'link_hash': "47f6e09ed92bc7585d88f66d96a72a5fb"}
    #
    #     print(api.create_shared_link(file2).text)


if __name__ == '__main__':
    main()
