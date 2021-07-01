import atexit
from pprint import pprint
from time import time, sleep
import schedule

from src.api import API
from src.sync import Sync


# TODO: client settings
# TODO: save tokens to file

class Client:
    def __init__(self, user, host, base_local_folder, base_remote_folder, ssl=False):
        self.base_local_folder = base_local_folder

        self.api = API(host, user['username'], base_remote_folder, ssl=ssl)
        self.sync = Sync(self.api, './src/rsync', base_remote_folder)

        self.user = user
        atexit.register(self.sync_folder, repeat=True)

    def login(self):
        r = self.api.login(self.user['username'], self.user['password'])
        if r.status_code != 200:
            print(f"Can't login {r.status_code} {r.text}")
            return 0
        return 1

    def sync_folder(self, repeat=False):
        print(f"Syncing {self.base_local_folder}")
        self.sync.sync_folder(self.base_local_folder, self.base_local_folder, nthreads=1, repeat=repeat)


def test_upload(api):
    """
        WS: --- Run time: ~20 seconds ---
        HTTP: --- Run time: ~11 seconds ---
    """
    if api.filer_delete_folder("Platform_designer_lab").status_code >= 300:
        print('delete error')
    start_time = time()
    results = api.filer_upload_folder(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab",
                            r"C:\Content\VUS\Efremov\TA\3_4_kurs", recursive=True, retry=False)
    print(results)
    print("\n\n--- Run time: %s seconds ---\n\n" % (round(time() - start_time, 5)))

    sleep(1)

    # api.filer_delete_folder("Platform_designer_lab")
    # start_time = time()
    # api.ws_upload_folder(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab",
    #                      r"C:\Content\VUS\Efremov\TA\3_4_kurs", sync, recursive=True)
    # print("\n\n--- Run time: %s seconds ---\n\n" % (round(time() - start_time, 5)))


def test_locks(api, full_remote_path):
    api.filer_set_file_lock(full_remote_path)
    _, lock = api.filer_get_file_lock(full_remote_path)
    print(lock)
    api.filer_remove_file_tag(full_remote_path)


def main():
    user = {"username": "test2", "password": "4321", "email": "test2_email"}
    user2 = {"username": "test3", "password": "54321", "email": "test3_email"}
    user3 = {"username": "test4", "password": "54321", "email": "test4_email"}
    host = "192.168.0.2"
    # host = "localhost"
    api = API(host, user['username'], '', ssl=False)
    sync = Sync(api, './rsync', '')

    # print(api.register(*user3.values()).text)
    # print(api.confirm_user(user3['username'], 'uparoueeiaeeooaaieao').text)
    # return

    # r = api.login(user['username'], user['password'])
    # if r.status_code != 200:
    #     print(f"Can't login {r.status_code} {r.text}")
    #     return

    # api.ws_meta_subscribe_update('/' + api.username + '/' + 'base_1' + '/')

    # if api.filer_delete_folder("Platform_designer_lab").status_code >= 300:
    #     print('delete error')

    # test_upload(api)
    # api.filer_remove_file_lock('Platform_designer_lab/Platform_designer_lab.docx')
    # print(sync.sync_folder(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab",
    #                        r"C:\Content\VUS\Efremov\TA\3_4_kurs", nthreads=10))
    # api.filer_delete_file("local.docx")
    # api.filer_delete_folder("Test")

    # print(api.filer_download_folder('Platform_designer_lab', './Test', True, nthreads=10))
    # pprint(api.filer_get_folder_listing("Platform_designer_lab", False, {'namePattern': 'заметки*'}))

    # print(api.version_downgrade(-1, 'Platform_designer_lab.docx').text)
    # print(api.version_list('Platform_designer_lab.docx').text)

    # r = api.filer_get_folder_listing("Platform_designer_lab/", recursive=False)
    # pprint(r)
    # print(api.filer_delete_file('Platform_designer_lab/ссылки.txt'))

    # print(API.hello_word().text)

    # print(API.download_public_shared_file("253c5bbe220c9bc39e630b4ec61670fca", r"C:\Users\Nikita\Desktop\VHDL.pptx"))

    # pprint(sync.sync_folder_listing(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab",
    #                                 r"C:\Content\VUS\Efremov\TA\3_4_kurs"))

    # print(api.filer_upload_file_2(r"C:\Content\VUS\Diploma\GUI\test_data\hello.docx",
    #                               r"C:\Content\VUS\Diploma\GUI\test_data", {}, remote_filename='test2/hello.docx'))

    # print(api.filer_download_file('Platform_designer_lab/Platform_designer_lab.docx', '.')[0].text)

    # API.filer_download_folder('', '..', recursive=True)

    file3 = {'path': 'Platform_designer_lab/Platform_designer_lab.pdf', 'exp_time': '0', 'type': 'group_testing', 'permission': 'r'}
    # print(api.share_create_link(file3).text)
    # print(api.share_remove_link({'path': file3['path'], 'link': ""}))

    folder = {'path': 'Platform_designer_lab/', 'exp_time': '0', 'type': 'group_testing', 'permission': 'rw'}
    # print(api.share_create_link(folder).text)
    # print(api.share_remove_link({'path': file3['path'], 'link': "6be975ba69ead63571b0cedab70fbad9b"}))

    # api.filer_download_zip_folder("Platform_designer_lab", '.')
    # print(api.admin_set_group_for_user("test2", "testing"))


def main2():
    # import sys
    import logging
    from watchdog.events import LoggingEventHandler
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    logging.basicConfig(level=logging.DEBUG)

    class MyEventHandler(FileSystemEventHandler):
        def catch_all_handler(self, event):
            logging.debug(event)

        def on_moved(self, event):
            self.catch_all_handler(event)

        def on_created(self, event):
            self.catch_all_handler(event)

        def on_deleted(self, event):
            self.catch_all_handler(event)

        def on_modified(self, event):
            print('heelo')
            self.catch_all_handler(event)


    if __name__ == "__main__":
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
        path = r"C:\Content\VUS\Python" # sys.argv[1] if len(sys.argv) > 1 else '.'
        event_handler = MyEventHandler() # LoggingEventHandler()
        observer = Observer()
        observer.schedule(event_handler, path, recursive=True)
        observer.start()
        try:
            while observer.isAlive():
                observer.join(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()


def main22():
    user = {"username": "test2", "password": "4321", "email": "test2_email"}
    # host = "192.168.0.2"
    host = "localhost"
    to_sync = {
        r"D:\tests\Lab_1": 'base_1',
        r"D:\tests\uchebnaya": 'base_2'
    }

    # TODO: filter to not sync temp files by name
    for base, remote in to_sync.items():
        client = Client(user, host, base, remote)
        if not client.login():
            return
        client.sync_folder(repeat=True)
        schedule.every(8).to(16).seconds.do(client.sync_folder)

    while 1:
        n = schedule.idle_seconds()
        if n is None:
            # no more jobs
            break
        elif n > 0:
            # sleep exactly the right amount of time
            sleep(n)
        schedule.run_pending()


if __name__ == '__main__':
    main()
