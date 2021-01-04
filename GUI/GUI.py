import abc
import tkinter
# Lots of tutorials have from tkinter import *, but that is pretty much always a bad idea
from tkinter import ttk, tix

from PIL import ImageTk, Image
from reportlab.graphics import renderPM
from svglib.svglib import svg2rlg


class Menubar(ttk.Frame):
    """Builds a menu bar for the top of the main window"""

    def __init__(self, parent, **kwargs):
        """ Constructor"""
        ttk.Frame.__init__(self, parent, **kwargs)
        self.root = parent
        self.init_menubar()

    @staticmethod
    def on_exit():
        """Exits program"""
        quit()

    def display_help(self):
        """Displays help document"""
        pass

    def display_about(self):
        """Displays info about program"""
        pass

    def init_menubar(self):
        self.menubar = tkinter.Menu(self.root)
        self.menu_file = tkinter.Menu(self.menubar)  # Creates a "File" menu
        self.menu_file.add_command(label='Exit', command=self.on_exit)  # Adds an option to the menu
        self.menubar.add_cascade(menu=self.menu_file,
                                 label='File')  # Adds File menu to the bar. Can also be used to create submenus.

        self.menu_help = tkinter.Menu(self.menubar)  # Creates a "Help" menu
        self.menu_help.add_command(label='Help', command=self.display_help)
        self.menu_help.add_command(label='About', command=self.display_about)
        self.menubar.add_cascade(menu=self.menu_help, label='Help')

        self.root.config(menu=self.menubar)


class Window(ttk.Frame):
    """Abstract base class for a popup window"""
    __metaclass__ = abc.ABCMeta

    def __init__(self, parent):
        """ Constructor """
        ttk.Frame.__init__(self, parent)
        self.parent = parent
        self.parent.resizable(width=False, height=False)  # Disallows window resizing
        self.validate_notempty = (self.register(self.notEmpty),
                                  '%P')  # Creates Tcl wrapper for python function. %P = new contents of field after the edit.
        self.init_gui()

    @abc.abstractmethod  # Must be overwriten by subclasses
    def init_gui(self):
        """Initiates GUI of any popup window"""
        pass

    @abc.abstractmethod
    def do_something(self):
        """Does something that all popup windows need to do"""
        pass

    def notEmpty(self, P):
        """Validates Entry fields to ensure they aren't empty"""
        if P.strip():
            valid = True
        else:
            print("Error: Field must not be empty.")  # Prints to console
            valid = False
        return valid

    def close_win(self):
        """Closes window"""
        self.parent.destroy()


class SomethingWindow(Window):
    """ New popup window """

    def init_gui(self):
        self.parent.title("New Window")
        self.parent.columnconfigure(0, weight=1)
        self.parent.rowconfigure(3, weight=1)

        # Create Widgets

        self.label_title = ttk.Label(self.parent, text="This sure is a new window!")
        self.contentframe = ttk.Frame(self.parent, relief="sunken")

        self.label_test = ttk.Label(self.contentframe, text='Enter some text:')
        self.input_test = ttk.Entry(self.contentframe, width=30, validate='focusout',
                                    validatecommand=(self.validate_notempty))

        self.btn_do = ttk.Button(self.parent, text='Action', command=self.do_something)
        self.btn_cancel = ttk.Button(self.parent, text='Cancel', command=self.close_win)

        # Layout
        self.label_title.grid(row=0, column=0, columnspan=2, sticky='nsew')
        self.contentframe.grid(row=1, column=0, columnspan=2, sticky='nsew')

        self.label_test.grid(row=0, column=0)
        self.input_test.grid(row=0, column=1, sticky='w')

        self.btn_do.grid(row=2, column=0, sticky='e')
        self.btn_cancel.grid(row=2, column=1, sticky='e')

        # Padding
        for child in self.parent.winfo_children():
            child.grid_configure(padx=10, pady=5)
        for child in self.contentframe.winfo_children():
            child.grid_configure(padx=20, pady=20)

    def do_something(self):
        '''Does something'''
        text = self.input_test.get().strip()
        if text:
            # Do things with text
            self.close_win()
        else:
            print("Error: But for real though, field must not be empty.")


class QuickAccessFile(ttk.Frame):
    """ Builds a quick access file"""

    def __init__(self, parent, filepath, **kwargs):
        """ Constructor"""
        ttk.Frame.__init__(self, parent, **kwargs)
        self.parent = parent
        self.filepath = filepath
        self.init_qaf()

    def get_filename(self):
        # TODO
        return self.filepath

    def get_file_icon(self):
        drawing = svg2rlg("img/document.svg")
        self._img = renderPM.drawToPIL(drawing)
        i = ImageTk.PhotoImage(self._img)

        # self.img = tkinter.Canvas(self)
        # self.img.image = i
        # self._image_on_canvas = self.img.create_image(0, 0, image=i, anchor='nw')
        self.img = ttk.Label(self, image=i)
        self.img.image = i

    def __resize_image(self, event):
        new_width = int(event.width / 2)
        new_height = int(event.height / 2)
        # print(new_height, new_width)
        new_img = self._img.resize((new_width, new_height))
        new_i = ImageTk.PhotoImage(new_img)

        self.img.image = new_i
        self.img.itemconfig(self._image_on_canvas, image=new_i)

    def resize_image(self, event):
        new_width = int(event.width / 2)
        new_height = int(event.height / 2)
        if new_width <= 0 or new_height <= 0:
            return
        # print(new_height, new_width)
        new_img = self._img.resize((new_width, new_height))
        new_i = ImageTk.PhotoImage(new_img)

        self.img.configure(image=new_i)
        self.img.image = new_i

    def init_qaf(self):
        # self.frame = ttk.Frame(self.parent, borderwidth=5, relief="ridge")
        self.get_file_icon()
        self.text = ttk.Label(self, text=self.get_filename())

        self.grid_columnconfigure(0, weight=0)
        self.grid_rowconfigure(0, weight=0)

        self.img.grid(row=0, column=0)
        self.text.grid(row=1, column=0)

        for child in self.winfo_children():
            child.grid_configure(padx=10, pady=5, sticky='s')


class GUI(ttk.Frame):
    """Main GUI class"""

    menubar = None

    def __init__(self, parent, **kwargs):
        ttk.Frame.__init__(self, parent, **kwargs)
        self.root = parent
        self.init_gui()

    # def openwindow(self):
    #     self.main_win = tkinter.Toplevel(self.root) # Set parent
    #     SomethingWindow(self.main_win)

    def init_gui(self):  # self - main frame
        # _ Main window settings _ #
        self.root.title('Test GUI')
        self.root.geometry("1200x600")
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.option_add('*tearOff', 'FALSE')  # Disables ability to tear menu bar into own window

        # _ Menu Bar _ #
        self.menubar = Menubar(self.root)

        # _ Main frame settings _ #
        self.grid_columnconfigure(0, weight=1)  # Allows column to stretch upon resizing
        self.grid_rowconfigure(0, weight=1)  # Same with row
        self.grid(column=0, row=0, sticky='nsew')

        #
        # _ Create Widgets _ #
        # Content frames
        self.categories = ttk.Frame(self, borderwidth=5, relief="ridge")
        self.search_user = ttk.Frame(self, borderwidth=5, relief="ridge")
        self.quick_access = ttk.Frame(self, borderwidth=5, relief="ridge")
        self.recent = ttk.Frame(self, borderwidth=5, relief="ridge")

        # Element frames
        self.quick_access_tiles = ttk.Frame(self.quick_access)

        # Labels
        self.quick_access_label = ttk.Label(self.quick_access, text='Быстрый доступ')

        # Buttons
        self.upload_btn = ttk.Button(self.categories, text='+ Создать')
        # self.btn = ttk.Button(self, text='Open Window', command=self.openwindow)

        # Other
        self.search = ttk.Entry(self.search_user)

        # TODO: переделать создание
        self.qafs = list()
        self.qafs.append(QuickAccessFile(self.quick_access_tiles, 'Document.doc'))
        self.qafs.append(QuickAccessFile(self.quick_access_tiles, 'Presentation.pptp'))
        self.qafs.append(QuickAccessFile(self.quick_access_tiles, 'Folder'))
        self.qafs.append(QuickAccessFile(self.quick_access_tiles, 'Table.xls'))
        self.qafs.append(QuickAccessFile(self.quick_access_tiles, 'Hello.pdf'))

        # Frames settings
        self.categories.grid_columnconfigure(0, weight=1) # , minsize=50
        self.categories.grid_rowconfigure(0, weight=1)
        self.search_user.grid_columnconfigure(0, weight=1)
        self.search_user.grid_rowconfigure(0, weight=1)
        self.quick_access.grid_columnconfigure(0, weight=1)
        self.quick_access.grid_rowconfigure(0, weight=1)
        self.recent.grid_columnconfigure(0, weight=1)
        self.recent.grid_rowconfigure(0, weight=1)

        # Element frames settings
        self.quick_access_tiles.grid_columnconfigure(0, weight=1)
        self.quick_access_tiles.grid_rowconfigure(0, weight=1)

        #
        # _ Layout using grid _ #
        # Content frames
        self.categories.grid(row=0, column=0, rowspan=3, sticky='nsew')
        self.search_user.grid(row=0, column=1, sticky='nsew')
        self.quick_access.grid(row=1, column=1, sticky='nsew')
        self.recent.grid(row=2, column=1, sticky='nsew')

        # Element frames
        self.quick_access_tiles.grid(row=1, column=0, sticky='nsew')

        # Elements
        self.upload_btn.grid(row=0, column=0, sticky='n')
        self.search.grid(row=0, column=0, sticky='w')
        self.quick_access_label.grid(row=0, column=0, sticky='nw')

        for i in range(len(self.qafs)):
            self.qafs[i].grid(row=0, column=i)

        # self.btn.grid(row=0, column=0, sticky='ew')

        # Padding
        for child in self.quick_access_tiles.winfo_children():
            child.grid_configure(padx=7, pady=7)

        #
        # _ Events _ #
        # self.root.bind('<Configure>', self.resize_images)

    def resize_images(self, event):
        for qaf in self.qafs:
            qaf.resize_image(event)


if __name__ == '__main__':
    root = tix.Tk() # tkinter.Tk()
    GUI(root)
    root.mainloop()
