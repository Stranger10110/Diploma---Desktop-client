import atexit
import json
import time
from datetime import datetime
from getpass import getpass
from os import makedirs
from tkinter import Tk, filedialog

import schedule
from consolemenu import *
from consolemenu.format import *
from consolemenu.items import *
from consolemenu.menu_component import Dimension
# from pyfiglet import Figlet

from src.api import API
from src.sync import Sync


class Client:
    def __init__(self, user, host, base_local_folder, base_remote_folder, ssl=False):
        self.base_local_folder = base_local_folder

        self.api = API(host, user['username'], base_remote_folder, ssl=ssl)
        self.sync = Sync(self.api, './rsync', base_remote_folder)

        self.user = user
        atexit.register(self.sync_folder, repeat=False, repeat_time=0)

    def login(self):
        r = self.api.login(self.user['username'], self.user['password'])
        if r.status_code != 200:
            print(f"Can't login {r.status_code} {r.text}")
            return 0
        return 1

    def sync_folder(self, repeat, repeat_time):
        print(f'{datetime.now().strftime("%d.%m.%Y %H:%M")} | Синхронизация папки {self.base_local_folder}')
        self.sync.sync_folder(self.base_local_folder, self.base_local_folder, nthreads=10, repeat=repeat, repeat_time=repeat_time) # TODO: change nthreads


class Console:
    # Create the root menu
    menu_format = MenuFormatBuilder(max_dimension=Dimension(width=100, height=50)) \
        .set_border_style_type(MenuBorderStyleType.LIGHT_BORDER) \
        .set_prompt("Выберите_пункт>") \
        .set_title_align('center') \
        .set_subtitle_align('center') \
        .set_left_margin(4) \
        .set_right_margin(4) \
        .show_header_bottom_border(True)

    to_sync = dict()
    user = {'username': '', 'password': ''}
    host = ''

    # def __init__(self):
    #     atexit.register(self.save_settings)

    def save_settings(self):
        makedirs('./data', exist_ok=True)
        with open('./data/settings.json', 'w') as file:
            json.dump({'folders': self.to_sync, 'host': self.host, 'username': self.user['username']}, file)

    def load_settings(self, folders_menu, host_item):
        try:
            with open('./data/settings.json', 'r') as file:
                settings = json.load(file)
            self.to_sync = settings['folders']

            for k, v in self.to_sync.items():
                item = FunctionItem(f"{k} : {v}", self.change_sync_path)
                item.args = (item,)
                folders_menu.append_item(item)

            self.host = settings['host']
            host_item.text = f"Адрес сервера (текущий '{self.host}')"

            self.user['username'] = settings['username']
        except FileNotFoundError:
            pass
        except KeyError:
            pass
        except json.decoder.JSONDecodeError:
            pass

    # TODO: change time
    def client_syncing(self, repeat=True, repeat_time=12):
        # user = {"username": "test2", "password": "4321", "email": "test2_email"}
        # host = "192.168.0.2"
        # host = "localhost"
        # to_sync = {
        #     r"D:\tests\Lab_1": 'base_1',
        #     r"D:\tests\uchebnaya": 'base_2'
        # }

        if len(self.to_sync) == 0 or self.host == '':
            Screen().input("Нужно задать настройки! Нажмите [Enter], чтобы вернуться...")
            return

        self.save_settings()

        logins = 0
        for base, remote in self.to_sync.items():
            client = Client(self.user, self.host, base, remote)
            login = client.login()

            if not login:
                if self.user['username'] == '':
                    self.user['username'] = input('\nВведите логин: ')
                self.user['password'] = getpass('Введите пароль: ')
                login = client.login()
                if not login:
                    continue

            self.save_settings()
            client.sync_folder(repeat, repeat_time)
            schedule.every(8).to(16).seconds.do(client.sync_folder, repeat, repeat_time)  # TODO change to minutes
            logins += 1

        if not logins:
            Screen().input("Введите [Enter], чтобы вернуться...")
            return

        while 1:
            n = schedule.idle_seconds()
            if n is None:
                # no more jobs
                break
            elif n > 0:
                # sleep exactly the right amount of time
                time.sleep(n)
            schedule.run_pending() # TODO: change time

    def set_ip_address(self, menu_item):
        ip = input("Введите IP адрес сервера (ip:port): ")
        self.host = ip
        menu_item.text = f"IP адрес сервера (текущий '{self.host}')"

    @staticmethod
    def input_folders():
        root = Tk()
        root.withdraw()
        local = filedialog.askdirectory()
        print(f"Выбранная локальная папка: '{local}'")

        root.destroy()
        if not len(local):
            return '', ''

        remote = input("Укажите папку на сервере (например, 'папка_1/папка_2'): ")
        return local, remote

    def change_sync_path(self, menu_item):
        local, remote = self.input_folders()
        if not len(local):
            return
        menu_item.text = f"{local} : {remote}"
        self.to_sync[local] = remote

    def add_sync_folder(self, menu):
        local, remote = self.input_folders()
        if not len(local):
            return
        item = FunctionItem(f"{local} : {remote}", self.change_sync_path)
        item.args = (item,)

        menu.append_item(item)
        self.to_sync[local] = remote

    def run(self):
        # f = Figlet(font='slant')
        # print(f.renderText('Filer'))
        # time.sleep(0.4)

        menu = ConsoleMenu("Filer", "Приложение для синхронизации файлов с облачным сервером",
                           formatter=self.menu_format, exit_option_text="Выйти")

        settings_submenu = ConsoleMenu("Настройки", "", formatter=self.menu_format, show_exit_option=False)
        settings_submenu.append_item(SelectionItem("Назад", 1))

        item_1 = SubmenuItem("Настройки", submenu=settings_submenu)
        item_1.set_menu(menu)

        folders_menu = ConsoleMenu("Синхронизируемые папки",
                                   "(нажмите на уже добавленную папку, чтобы изменить её)",
                                   formatter=self.menu_format, show_exit_option=False)
        folders_menu.append_item(SelectionItem("Назад", 1))
        folders_menu.append_item(FunctionItem("Добавить папку", self.add_sync_folder, args=(folders_menu,)))
        item_2 = SubmenuItem("Папки", submenu=folders_menu)
        item_2.set_menu(settings_submenu)

        settings_submenu.append_item(item_2)
        item = FunctionItem(f"Адрес сервера (текущий '{self.host}')", self.set_ip_address)
        item.args = (item,)
        settings_submenu.append_item(item)

        self.load_settings(folders_menu, item)
        # if self.user['username'] == '':
        #     self.user['username'] = input('\n   Filer\nВведите логин: ')
        # self.save_settings()

        # Add all the items to the root menu
        menu.append_item(FunctionItem("Запустить синхронизацию", self.client_syncing))
        menu.append_item(item_1)

        # Show the menu
        menu.start()
        menu.join()


def main():
    console = Console()
    console.run()


if __name__ == '__main__':
    main()
