import concurrent.futures
import mimetypes
import os
from concurrent.futures.thread import ThreadPoolExecutor
from json import dumps as json_dumps
from pathlib import Path
from time import time as current_time, sleep

import magic
import requests
from requests_toolbelt import MultipartEncoder
from tenacity import retry, stop_after_attempt

from src.sync import Sync

mime = magic.Magic(mime=True)

from websocket import create_connection as ws_create_connection, _exceptions as ws_exceptions

# wf = filer.WeedFiler()


class WsResponse:
    def __init__(self, code, text, headers):
        self.status_code = code
        self.text = text
        self.headers = headers


def request(func):
    def wrapper(self, *args, **kwargs):
        if not self.check_tokens():
            return WsResponse(0, 'login required', None)

        r = func(self, *args, **kwargs)
        if self.update_tokens_required:
            self.update_tokens(r)

        return r

    return wrapper


def async_request(func):
    async def wrapper(self, *args, **kwargs):
        if not self.check_tokens():
            return WsResponse(0, 'login required', None)

        r = await func(self, *args, **kwargs)
        if self.update_tokens_required:
            self.update_tokens(r)

        return r

    return wrapper


# TODO: hash password in client ?


class API:
    def __init__(self, host, username, ssl=False):
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

    def download_file(self, url, filepath):
        with self.session.get(url, stream=True) as r:
            r.raise_for_status()

            Path(os.path.dirname(filepath)).mkdir(parents=True, exist_ok=True)
            with open(filepath, 'wb') as f:
                for chunk in r.iter_content(chunk_size=3_145_728):  # 3 MB
                    # If you have chunk encoded response uncomment if
                    # and set chunk_size parameter to None.
                    # if chunk:
                    f.write(chunk)
            return WsResponse(r.status_code, 'Successful download', r.headers)

    @request
    def hello_word(self):
        r = self.session.get(f"{self.protocol}://{self.host}/api/restricted_hello")
        return r


    @request
    def upload_folder_by_ws(self, root_dir: str, base_path: str):
        try:
            ws = ws_create_connection(f"ws://{self.host}/api/upload_files", header=dict(self.session.headers))
            tcp_socket = ws.sock
        except ws_exceptions.WebSocketBadStatusException as e:
            split = str(e).split()
            code = split[2]
            text = ' '.join(split[3:])

            r = WsResponse(code, text, None)
            return r

        sync = Sync()
        sync.sync_folder(root_dir, base_path, ws, tcp_socket)

        while ws.recv() != 'next':
            sleep(0.0001)
        ws.send(r'stop###')
        ws.close()
        r = WsResponse(200, f'{root_dir} successful', ws.getheaders())
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

    # async def filer_req(self, func, rel_path: str, filenames: Iterable, params: dict, async_=False):
    #     if not async_:
    #         r = func()
    #     else:
    #         pass
    #     return r
    #
    # @request
    # async def upload(self, full_folder_path: str, base_path: str, filer_params: dict):
    #     full_folder_path = full_folder_path.replace("\\", '/')
    #     base_path = base_path.replace("\\", '/')
    #
    #     for dir_path, dir_names, filenames in os.walk(full_folder_path):
    #
    #     # if recursive and len(dir_names) > 0:
    #     #     for folder in dir_names:
    #     #         return await self.upload_folder_to_filer(f"{dir_path}/{folder}", base_path, filer_params)
    #
    #         filenames = [f"{full_folder_path}/{x}" for x in filenames]
    #         files = [Sync.async_file_reader(x) for x in filenames]
    #         # fs = {'f': x for x in files}
    #
    #         async def func(async_=False, session=None):
    #             # self.session.post(f"{self.protocol}://{self.host}/api/filer/", files=fs)
    #             if async_:
    #                 for file in files:
    #                     with aiohttp.MultipartWriter('mixed') as mpwriter:
    #                         mpwriter.append(file)
    #                         async with session.post(f"{self.protocol}://{self.host}/api/filer/", data=mpwriter) as resp:
    #                             if not (200 <= resp.status <= 299):
    #                                 return WsResponse(resp.status, await resp.text(), resp.headers)
    #             else:
    #                 for file in files:
    #                     resp = self.session.post(f"{self.protocol}://{self.host}/api/filer/", files={'': file})
    #                     if not (200 <= resp.status_code <= 299):
    #                         return resp
    #             return resp
    #
    #         r = await self.make_filer_request(func, filenames, base_path, filer_params, async_=True)
    #     return r
    #
    # @async_request
    # async def upload_folder_to_filer(self, full_folder_path: str, base_path: str, filer_params: dict):
    #     full_folder_path = full_folder_path.replace("\\", '/')
    #     base_path = base_path.replace("\\", '/')
    #
    #     json = {'params': filer_params}
    #     for dir_path, _, filenames in os.walk(full_folder_path):
    #         rel_path = self.remove_prefix(dir_path, f"{base_path}/")
    #         json['path'] = f"{rel_path}/" # f"{rel_path}/{file}"
    #         json_str = json_dumps(json, separators=(',', ':'))
    #
    #         headers = self.session.headers.copy()
    #         headers["Filer-json"] = json_str
    #
    #         #mpwriter = aiohttp.MultipartWriter('form-data')
    #         data = aiohttp.FormData()
    #         for i, file in enumerate(filenames):
    #             filepath = f"{dir_path}/{file}"
    #             content = magic.from_file(filepath, mime=True)
    #             data.add_field(f'file_{i}', Sync.async_file_reader(filepath),
    #                            filename=file, content_type=content)
    #             # part = mpwriter.append(Sync.async_file_reader(f"{dir_path}/{file}"))
    #             # part.set_content_disposition('attachment', filename=file)
    #
    #         async with aiohttp.ClientSession(headers=headers) as session:
    #             async with session.post(f"{self.protocol}://{self.host}/api/filer/", data=data) as resp:
    #                 r = WsResponse(resp.status, await resp.text(), resp.headers)
    #
    #     return r
    #

    # TODO: add retry uploading from last uploaded chunk
    @request
    def upload_folder_to_filer(self, full_folder_path: str, base_path: str, filer_params: dict):
        full_folder_path = full_folder_path.replace("\\", '/')
        base_path = base_path.replace("\\", '/')

        # json = {'params': filer_params}
        futures = list()
        results = list()
        with ThreadPoolExecutor(10) as pool:
            for dir_path, _, filenames in os.walk(full_folder_path):
                dir_path = dir_path.replace("\\", '/')
                rel_path = Sync.remove_prefix(dir_path, f"{base_path}/")
                # json['path'] = f"{rel_path}/" # f"{rel_path}/{file}"

                # resp = self.post(filenames, dir_path, headers)
                for file in filenames:
                    # if file not in ('заметки.txt', 'IMG_20201110_220652.jpg'):
                    #     continue
                    # json = {'params': filer_params, 'path': f"{rel_path}/{file}"}
                    # json_str = json_dumps(json, separators=(',', ':'))
                    # headers = self.session.headers
                    # headers["Filer-json"] = json_str
                    # # self.curl_headers = dict()
                    #
                    # filepath = f"{dir_path}/{file}"
                    # print(headers["Filer-json"])
                    futures.append(pool.submit(self.posttt, file, dir_path, rel_path, filer_params))

            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        return results
    #
    # async def post_to_filer(self, headers, data):
    #     try:
    #         self.session.headers["Filer-json"] = '{"params":{},"path":"Hollow_Knight_Fragile_flower/"}'
    #         # data = aiohttp.FormData()
    #         # data.add_field('file', open(r'H:\Downloads\hollow\Hollow_Knight_Fragile_flower\output_log.txt', 'rb'),
    #         #                 filename='output_log.txt', content_type='text/plain')
    #         async with aiohttp.ClientSession(headers=self.session.headers) as session:
    #             resp = await session.post(f"{self.protocol}://{self.host}/api/filer/", data={'f': open(r'H:\Downloads\hollow\Hollow_Knight_Fragile_flower\output_log.txt', 'rb')})
    #     except ClientConnectorError as e:
    #         return WsResponse(500, f"Python ClientConnectorError: {e}", dict())
    #     return WsResponse(resp.status, await resp.text(), resp.headers)

    # @staticmethod
    # @gen.coroutine
    # def multipart_producer(boundary, filenames, dir_path, write):
    #     boundary_bytes = boundary.encode()
    #
    #     for filename in filenames:
    #         filename_bytes = filename.encode()
    #         mtype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    #         buf = (
    #                 (b"--%s\r\n" % boundary_bytes)
    #                 + (
    #                         b'Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
    #                         % (filename_bytes, filename_bytes)
    #                 )
    #                 + (b"Content-Type: %s\r\n" % mtype.encode())
    #                 + b"\r\n"
    #         )
    #         yield write(buf)
    #         with open(f'{dir_path}/{filename}', "rb") as f:
    #             while True:
    #                 # 16k at a time.
    #                 chunk = f.read(16 * 1024)
    #                 if not chunk:
    #                     break
    #                 yield write(chunk)
    #
    #         yield write(b"\r\n")
    #
    #     yield write(b"--%s--\r\n" % (boundary_bytes,))
    #
    # # Using HTTP PUT, upload one raw file. This is preferred for large files since
    # # the server can stream the data instead of buffering it entirely in memory.
    # @gen.coroutine
    # def post(self, filenames, dir_path, headers):
    #     boundary = uuid4().hex
    #     headers["Content-Type"] = "multipart/form-data; boundary=%s" % boundary
    #     producer = partial(self.multipart_producer, boundary, filenames)
    #     response = yield self.async_client.fetch(
    #             f"{self.protocol}://{self.host}/api/filer/",
    #             method="POST",
    #             headers=headers,
    #             body_producer=producer,
    #     )
    #
    #     return response

    # def save_curl_headers(self, header_line):
    #     header_line = header_line.decode('iso-8859-1')
    #
    #     # Ignore all lines without a colon
    #     if ':' not in header_line:
    #         return
    #
    #     # Break the header line into header name and value
    #     h_name, h_value = header_line.split(':', 1)
    #
    #     # Remove whitespace that may be present
    #     h_name = h_name.strip()
    #     h_value = h_value.strip()
    #     # h_name = h_name.lower() # Convert header names to lowercase
    #     self.curl_headers[h_name] = h_value # Header name and value

    @retry(stop=stop_after_attempt(3))
    def posttt(self, filename, dir_path, rel_path, filer_params):
        filepath = f"{dir_path}/{filename}"
        filesize = os.path.getsize(filepath)
        if filesize == 0:
            return WsResponse(205, "Zero size file", self.session.headers)

        json = {'par': filer_params, 'pat': f"{rel_path}/{filename}"}
        json_str = json_dumps(json, separators=(',', ':'))
        # headers = self.session.headers.copy()
        # headers["Filer-json"] = json_str
        # self.curl_headers = dict()

        mimetype = mimetypes.guess_type(filepath)[0] or ''
        m = MultipartEncoder(fields={'f': (None, open(filepath, 'rb'), mimetype)})
        m._read = m.read
        m.read = lambda size: m._read(1_048_576) # 1_048_576 if filesize >= 1_048_576 else filesize)

        headers = self.session.headers.copy()
        headers['Content-Type'] = m.content_type
        headers['Content-Length'] = str(filesize)

        # file_param = MultipartParam.from_file("f", filepath)
        # datagen, heads = multipart_encode([file_param])
        # headers.update(heads)
        # # req = urllib_Request(f"{self.protocol}://{self.host}/api/filer", data=datagen, headers=headers)
        # print(json['path'], headers["Filer-json"])
        headers.update({"Fi-js": json_str})
        r = requests.post(f"{self.protocol}://{self.host}/api/filer", data=m, headers=headers)
        self.session.headers = r.headers

        # r = hurl.post(f"{self.protocol}://{self.host}/api/filer", files=(('f', filepath),))
        return r # urlopen(req).read()

        # crl = pycurl.Curl()

        # crl.setopt(crl.HTTPPOST, [
        #     # (f'file', (crl.FORM_FILE, filepath
        #     #            ))
        #     ('fileupload', (
        #         crl.FORM_BUFFER, 'readme.txt',
        #         crl.FORM_BUFFERPTR, 'This is a fancy readme file',
        #     )),
        # ])

        # crl.setopt(crl.POST, 1)
        # crl.setopt(crl.READFUNCTION, FileReader(open(filepath, 'rb')).read_callback)
        # filesize = os.path.getsize(filepath)
        # crl.setopt(crl.POSTFIELDSIZE, filesize)
        #
        # headers['Content-Length'] = str(filesize)
        # crl.setopt(crl.HTTPHEADER, [f"{k}: {v}" for k, v in headers.items()])
        # crl.setopt(crl.HEADERFUNCTION, self.save_curl_headers)
        # crl.setopt(crl.VERBOSE, 1)
        #
        # crl.setopt(crl.URL, f"{self.protocol}://{self.host}/api/filer")

        # sync = Sync()
        # crl = sync.get_raw_poster(f"{self.protocol}://{self.host}/api/filer", filepath, [f"{k}: {v}" for k, v in headers.items()], self.save_curl_headers)

        # crl.perform()
        # crl.close()

        # curl_options = f'-F f=@`"{filepath.encode("utf-8")}"` -v '
        # for k, v in headers.items():
        #     curl_options += f'-H "{k}: {v}" '
        # os.system(fr"C:\Content\VUS\Diploma\Client\curl\curl.exe {curl_options} {f'{self.protocol}://{self.host}/api/filer'}")

        # return WsResponse(201, "cURL successful", self.curl_headers)
    #
    # @staticmethod
    # async def download_file(session: aiohttp.ClientSession, url: str, filepath):
    #     with open(filepath, 'wb') as file:
    #         async with session.get(url) as response:
    #             assert response.status == 200
    #             while True:
    #                 chunk = await response.content.read(3_145_728)
    #                 if not chunk:
    #                     break
    #                 file.write(chunk)
    #     return url
    #
    # @asyncio.coroutine
    # def download_multiple(self, session: aiohttp.ClientSession):
    #     urls = (
    #         'http://cnn.com',
    #         'http://nytimes.com',
    #         'http://google.com',
    #         'http://leagueoflegends.com',
    #         'http://python.org',
    #     )
    #     download_futures = [self.download_file(session, url) for url in urls]
    #     print('Results')
    #     for download_future in asyncio.as_completed(download_futures):
    #         result = yield from download_future
    #         print('finished:', result)
    #     return urls

    # @request
    # def download_file_from_filer(self, filepath: str, base_path: str, filer_params: dict):
    #     def func():
    #         self.download_file(f"{self.protocol}://{self.host}/api/filer/", )
    #     r = self.make_filer_request(func, filepath, base_path, filer_params)
    #     return r
    #
    # @request
    # def delete_file_from_filer(self, filepath: str, base_path: str, filer_params: dict):
    #     def func():
    #         self.session.delete(f"{self.protocol}://{self.host}/api/filer/")
    #     r = self.make_filer_request(func, filepath, base_path, filer_params)
    #     return r

    @request
    def download_file_from_filer(self, remote_path, local_folder_path):
        json = {'par': {}, 'pat': remote_path}
        json_str = json_dumps(json, separators=(',', ':'))
        self.session.headers["Fi-js"] = json_str

        url = f"{self.protocol}://{self.host}/api/filer"
        return self.download_file(url, f'{local_folder_path}/{remote_path}')


def main(x):
    # print(Sync.file_md5(r"H:\Downloads\KINGSTON\KINGSTON\Quartus_Desktop\MILI\MILI_Scheme.bdf"))
    user = {"username": "test2", "password": "4321", "email": "test2_email"}
    host = "192.168.0.2:8080"
    # api = API("mgtu-diploma.tk", user['username'])
    api = API(host, user['username'], ssl=False)

    # print(api.register(*user.values()).text)
    # print(api.confirm_user(user['username'], 'ebioovumogubigefumab').text)
    # return

    r = api.login(user['username'], user['password'])
    if r.status_code != 200:
        print(f"Can't login {r.status_code} {r.text}")
        return

    # print(api.hello_word().text)

    # print(api.download_public_shared_file("253c5bbe220c9bc39e630b4ec61670fca", r"C:\Users\Nikita\Desktop\VHDL.pptx"))
    # resp = asyncio.run(api.upload_folder_to_filer(r"H:\Downloads\hollow\Hollow_Knight_Fragile_flower", r"H:\Downloads\hollow", {}), debug=True) # 'maxMB': '1', 'collection': api.username
    # resp = api.upload_folder_to_filer(r"H:\Downloads\hollow\Hollow_Knight_Fragile_flower", r"H:\Downloads\hollow", {'maxMB': '1'})
    # resp = api.session.delete("http://13.53.193.254:8888/test2/Fragile flower (start)?recursive=true")

    # resps = api.upload_folder_to_filer(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab", r"C:\Content\VUS\Efremov\TA\3_4_kurs", {})
    # for resp in resps:
    #     print(resp.text)

    print(api.download_file_from_filer('Platform_designer_lab/Platform_designer_lab.pdf', '..').text)

    # if x == 1:
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
    # else:
    #     file2 = r"H:\Downloads\KINGSTON\KINGSTON\Quartus_Desktop\VHDL.pptx"
    #     print(api.upload_file(file2).text)


def run(*args):
    with concurrent.futures.ProcessPoolExecutor(max_workers=12) as executor:
        results = executor.map(main, (1, 2))


if __name__ == '__main__':
    main(1)
