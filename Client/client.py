from pprint import pprint
from time import time, sleep

from src.api import API
from src.sync import Sync


def test_upload(api, sync):
    """
        WS: --- Run time: ~20 seconds ---
        HTTP: --- Run time: ~11 seconds ---
    """
    api.filer_delete_folder("Platform_designer_lab")
    start_time = time()
    results = api.filer_upload_folder(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab",
                            r"C:\Content\VUS\Efremov\TA\3_4_kurs", recursive=True)
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
    api.filer_remove_file_tags(full_remote_path)


def main():
    user = {"username": "test2", "password": "4321", "email": "test2_email"}
    host = "192.168.0.2:8080"
    api = API(host, user['username'], ssl=False)
    sync = Sync(api, './src/rsync')

    # print(API.register(*user.values()).text)
    # print(API.confirm_user(user['username'], 'ebioovumogubigefumab').text)
    # return

    r = api.login(user['username'], user['password'])
    if r.status_code != 200:
        print(f"Can't login {r.status_code} {r.text}")
        return

    # api.filer_delete_folder("Platform_designer_lab")
    # test_upload(api, sync)
    # sync.sync_folder(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab",
    #                  r"C:\Content\VUS\Efremov\TA\3_4_kurs")

    # print(api.filer_remove_file_tags("Platform_designer_lab/заметки.txt"))
    pprint(api.filer_get_folder_listing("Platform_designer_lab", False, {'namePattern': 'заметки*'}))
    # api.filer_remove_file_tags("Platform_designer_lab/заметки.txt")

    # print(api.filer_remove_file_lock('Platform_designer_lab/заметки.txt'))
    # print(api.downgrade_file_to_version(-1, 'Platform_designer_lab/заметки.txt').text)

    # print(API.hello_word().text)

    # print(API.download_public_shared_file("253c5bbe220c9bc39e630b4ec61670fca", r"C:\Users\Nikita\Desktop\VHDL.pptx"))

    # test_upload(API)
    # pprint(sync.sync_folder_listing(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab",
    #                                 r"C:\Content\VUS\Efremov\TA\3_4_kurs"))
    # test_locks(API, 'Platform_designer_lab/Platform_designer_lab.pdf')

    # print(API.filer_upload_file_2(r"C:\Content\VUS\Efremov\TA\3_4_kurs\Platform_designer_lab\test.pdf",
    #                               r"C:\Content\VUS\Efremov\TA\3_4_kurs", {'op': 'append'},
    #                               remote_filename='Platform_designer_lab.pdf'))
    # print(API.filer_upload_file_2(r"C:\Content\VUS\Diploma\GUI\test_data\hello.docx",
    #                               r"C:\Content\VUS\Diploma\GUI\test_data", {}))

    # print(api.filer_download_file('Platform_designer_lab/заметки.txt', '.').text)

    # API.filer_download_folder('', '..', recursive=True)

    #     # file1 = r"H:\Downloads\KINGSTON\KINGSTON\Quartus_Desktop\MILI\MILI_Scheme.bdf"
    #     # print(API.sync_files(folder1).text)
    #
    #     # 253c5bbe220c9bc39e630b4ec61670fca
    #     file1 = {'path': 'Quartus_Desktop/VHDL.pptx', 'exp_time': '0', 'type': 'pub',
    #              'link_hash': '253c5bbe220c9bc39e630b4ec61670fca'}
    #
    #     # 1c55bed5427e543a5444a000ab2f9f5ab
    #     file2 = {'path': 'MILI/cache.zip', 'exp_time': '0', 'type': 'grp_test_group',
    #              'link_hash': "47f6e09ed92bc7585d88f66d96a72a5fb"}
    #
    #     print(API.create_shared_link(file2).text)


def main2():
    import sys
    import logging
    from watchdog.observers import Observer
    from watchdog.events import LoggingEventHandler

    if __name__ == "__main__":
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
        path = r"D:\Lab_1" # sys.argv[1] if len(sys.argv) > 1 else '.'
        event_handler = LoggingEventHandler()
        observer = Observer()
        observer.schedule(event_handler, path, recursive=True)
        observer.start()
        try:
            while observer.isAlive():
                observer.join(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()


if __name__ == '__main__':
    main()
