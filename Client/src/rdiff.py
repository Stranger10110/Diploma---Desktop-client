from ctypes import CDLL, c_char_p, c_int


class Rdiff:
    def __init__(self, dll_path):
        self.rsync = CDLL(dll_path)
        self.rsync.rdiff_set_params(c_int(0), c_int(0), c_int(1), c_int(1))

    def signature(self, filepath, sig_path):
        basis = c_char_p(bytes(filepath))
        sig = c_char_p(bytes(sig_path))
        self.rsync.rdiff_sig(basis, sig)

    def delta(self, sig_path, new_filepath, delta_path):
        sig = c_char_p(bytes(sig_path))
        new = c_char_p(bytes(new_filepath))
        delta = c_char_p(bytes(delta_path))
        self.rsync.rdiff_delta(sig, new, delta)

    def patch(self, filepath, delta_path, new_filepath):
        basis = c_char_p(bytes(filepath))
        delta = c_char_p(bytes(delta_path))
        new = c_char_p(bytes(new_filepath))
        self.rsync.rdiff_patch(basis, delta, new)
