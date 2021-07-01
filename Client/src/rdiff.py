import os
from ctypes import CDLL, c_char_p, c_int
from pathlib import Path
from sys import getdefaultencoding


class Rdiff:
    """
    Return Value
    0: Successful completion.
    1: Environmental problems (file not found, invalid options, IO error, etc).
    2: Corrupt signature or delta file.
    3: Internal error or unhandled situation in librsync or rdiff.
    """
    def __init__(self, dll_path):
        self.rsync = CDLL(dll_path)

        types = (c_int, c_int, c_int, c_char_p)
        self.rsync.rdiff_sig.argtypes = types[1:]
        self.rsync.rdiff_delta.argtypes = types
        self.rsync.rdiff_patch.argtypes = types

        self.rsync.rdiff_set_params(c_int(0), c_int(0), c_int(1), c_int(1))

    def signature(self, filepath, sig_path, sig_mode='wb'):
        try:
            basis_file = open(filepath, 'rb')
            basis_fd = basis_file.fileno()

            Path(os.path.dirname(sig_path)).mkdir(parents=True, exist_ok=True)
            sig_file = open(sig_path, sig_mode)
            sig_fd = sig_file.fileno()
            sig_mode_ = bytes(sig_mode, encoding=getdefaultencoding())
        except IOError:
            return 3

        res = self.rsync.rdiff_sig(basis_fd, sig_fd, sig_mode_)
        if res != 0:
            basis_file.close()
            sig_file.close()
        return res

    def delta(self, sig_path, new_filepath, delta_path, delta_mode='wb'):
        try:
            sig_file = open(sig_path, 'rb')
            sig_fd = sig_file.fileno()

            new_file = open(new_filepath, 'rb')
            new_fd = new_file.fileno()

            Path(os.path.dirname(delta_path)).mkdir(parents=True, exist_ok=True)
            delta_file = open(delta_path, delta_mode)
            delta_fd = delta_file.fileno()
            delta_mode_ = bytes(delta_mode, encoding=getdefaultencoding())
        except IOError:
            return 3

        res = self.rsync.rdiff_delta(sig_fd, new_fd, delta_fd, delta_mode_)
        if res != 0:
            sig_file.close()
            new_file.close()
            delta_file.close()
        return res

    def patch(self, filepath, delta_path, new_filepath, new_mode='wb'):
        try:
            basis_file = open(filepath, 'rb')
            basis_fd = basis_file.fileno()

            delta_file = open(delta_path, 'rb')
            delta_fd = delta_file.fileno()

            Path(os.path.dirname(new_filepath)).mkdir(parents=True, exist_ok=True)
            new_file = open(new_filepath, new_mode)
            new_fd = new_file.fileno()
            new_mode_ = bytes(new_mode, encoding=getdefaultencoding())
        except IOError:
            return 3

        res = self.rsync.rdiff_patch(basis_fd, delta_fd, new_fd, new_mode_)
        if res != 0:
            basis_file.close()
            delta_file.close()
            new_file.close()
        return res


def main():
    a = "C:/Content/VUS/Efremov/TA/3_4_kurs/Platform_designer_lab/заметки.txt"
    b = "C:/Content/VUS/Efremov/TA/3_4_kurs/Platform_designer_lab/заметки.txt.sig"
    rdiff = Rdiff("./rsync")
    # print(rdiff.signature(a, b))
    print(rdiff.patch(a, r"C:\Users\Nikita\Desktop\заметки.txt.delta.v2",
                      r"C:\Users\Nikita\Desktop\заметки_v1.txt"))
    print(rdiff.patch(r"C:\Users\Nikita\Desktop\заметки_v1.txt", r"C:\Users\Nikita\Desktop\заметки.txt.delta.v1",
                      r"C:\Users\Nikita\Desktop\заметки_v0.txt"))


if __name__ == '__main__':
    main()
