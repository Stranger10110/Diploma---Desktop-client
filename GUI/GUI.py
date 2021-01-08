import os
import sys

from PyQt5 import QtWidgets as QtW, QtGui as QtG, QtCore as QtC, __file__ as pyside_location, uic

# os.system(r"pyqt5-uic .\QtGUI.ui -o MainWindow.py")

# from MainWindow import Ui_MainWindow

# dirname = os.path.dirname(pyside_location)
# plugin_path = os.path.join(dirname, 'plugins', 'platforms')
# os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = plugin_path


class MainWindow(QtW.QMainWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # self.setupUi(self)
        uic.loadUi('QtGUI.ui', self)

        self.customise_files_tree()

    def customise_files_tree(self):
        model = QtW.QFileSystemModel()
        model.setRootPath('C:/')
        self.files_tree.setModel(model)
        self.files_tree.setRootIndex(model.index('./..'))
        # self.files_tree.setHeaderHidden(True)

        self.view_files.hide()

        # self.quick_acces_list.setFlow(QtW.QListView.LeftToRight)
        # self.quick_acces_list.setDragDropMode(QtW.QAbstractItemView.NoDragDrop)
        # self.quick_acces_list.setMovement(QtW.QListView.Static)
        # self.quick_acces_list.setUniformItemSizes(True)
        # self.quick_acces_list.setGridSize(QtC.QSize(frame_geometry.height() / 4.5, frame_geometry.height() / 4.5))
        # self.quick_acces_list.setResizeMode(QtW.QListView.Adjust)
        # self.quick_acces_list.setViewMode(QtW.QListView.IconMode)
        # self.quick_acces_list.setSpacing((self.frameGeometry().width() + self.frameGeometry().height()) / 80)
        # self.quick_acces_list.setIconSize(QtC.QSize(frame_geometry.height() / 6, frame_geometry.width() / 6))

        self.quick_access_list.itemDoubleClicked.connect(self.item_chosen)
        # self.display_files.itemChanged.connect(self.user_changed_list_item)
        # self.display_files.setContextMenuPolicy(QtC.Qt.CustomContextMenu)
        # self.display_files.customContextMenuRequested.connect(self.on_context_menu)
        self.update_display('.')

    # Called when user double clicks something in the display, routes to
    # open_details (if file) or update_ui (if directory)
    def item_chosen(self):

        cur = self.quick_access_list.currentItem().text()
        full_name = '.' + '/' + cur #self.current_location + '/' + cur

        # cover cases where we don't want to add delim because there already is one
        if cur == "/":
            full_name = '.' + '/' + cur # self.current_location + cur
        if len(cur) <= 3 and os.name == "nt":
            full_name = '.' + '/' + cur # self.current_location + cur

        if os.path.isdir(full_name):
            # self.current_location = full_name
            self.update_display(full_name)
            return

    def resizeEvent(self, event):
        # window_size = self.frameSize()
        frame_size = self.quick_access_list.frameSize()
        item_size = self.frameSize().height() / 8 # размер окна / 7
        # frame_size_w = frame_size.width()
        # frame_size_h = frame_size.height()
        # print(self.quick_acces_list.frameSize().width(), (window_size.width() / 6))
        self.quick_access_list.setIconSize(QtC.QSize(item_size, item_size))
        # self.quick_access_list.setIconSize(QtC.QSize(frame_size_w * 0.8, frame_size_h * 0.8))
        # self.quick_acces_list.setSpacing((window_size.width() + window_size.height()) / 70)
    #     frame_geometry = self.frameGeometry()
    #     self.quick_acces_list.setGridSize(QtC.QSize(frame_geometry.height() / 4.5, frame_geometry.height() / 4.5))
        width_margins = (frame_size.width() - item_size * 5) / 6
        height_margins = (frame_size.height() - item_size) / 3
        # print(self.quick_access_list.item(0).sizeHint(), self.quick_access_list.iconSize(), height_margins)
        # print(frame_size.width(), self.quick_access_list.iconSize(), width_margins)
        # print(margins, width, self.quick_access.frameSize(), self.frameSize().width() * 0.8333 - 24)
        self.quick_access_list.setStyleSheet('QListView::item{border:0px;margin-left:%dpx;margin-top:%dpx;}' % (
                                              width_margins, height_margins))

    def update_display(self, new_loc):
        elems = os.listdir(new_loc)
        self.quick_access_list.clear()
        for elem in elems[:5]:

            new_widget = QtW.QListWidgetItem(elem)
            elem = new_loc + '/' + elem

            if os.path.isdir(elem):
                new_widget.setIcon(QtG.QIcon("img/directory.png"))
            if os.path.isfile(elem):
                new_widget.setIcon(QtG.QIcon("img/file.png"))
                """if self.is_imagefile(elem):
                    new_widget.setIcon(QtG.QIcon("img/pic.png"))
                elif self.is_archive(elem):
                    new_widget.setIcon(QtG.QIcon("img/zip.png"))
                elif self.is_textfile(elem):
                    new_widget.setIcon(QtG.QIcon("img/file.png"))"""

            self.quick_access_list.addItem(new_widget)


if __name__ == '__main__':
    app = QtW.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
