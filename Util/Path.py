import copy
import os
import tempfile
import sys

from PyQt5 import QtWidgets, QtCore

RUNNING_DIRECTORY = QtCore.QFileInfo(os.getcwd()).canonicalFilePath()
RESOURCE_DIRECTORY = QtCore.QFileInfo(RUNNING_DIRECTORY + "\\Resource").canonicalFilePath()
TEMP_FILE_DIRECTORY = tempfile.TemporaryDirectory()
IMAGE_DIRECTORY = QtCore.QFileInfo(RUNNING_DIRECTORY + "\\Resource\\images").canonicalFilePath()
DLL_DIRECTORY = QtCore.QFileInfo(RUNNING_DIRECTORY + "\\Resource\\dll").canonicalFilePath()
PEM_DIRECTORY = QtCore.QFileInfo(RUNNING_DIRECTORY + "\\Resource\\pem").canonicalFilePath()
UI_DIRECTORY = QtCore.QFileInfo(RUNNING_DIRECTORY + "\\Resource\\ui").canonicalFilePath()
CONFIG_DIRECTORY = QtCore.QFileInfo(RUNNING_DIRECTORY + "\\Resource\\Config").canonicalFilePath()
MENU_DIRECTORY = QtCore.QFileInfo(RUNNING_DIRECTORY + "\\Menu").canonicalFilePath()
USER_DEFINED_PYTHON_FILE_DIRECTORY = QtCore.QFileInfo(RUNNING_DIRECTORY + "\\Menu\\UserDefinedMenu").canonicalFilePath()
ROOT_DIRECTORY = QtCore.QFileInfo(RUNNING_DIRECTORY + "\\Menu\\UserDefinedMenu").canonicalFilePath()
RUNTIME_DIRECTORY = QtCore.QFileInfo(RUNNING_DIRECTORY + "\\Resource\\runtime").canonicalFilePath()
LOGGING_DIRECTORY = QtCore.QFileInfo(RUNNING_DIRECTORY + "\\Resource\\log").canonicalFilePath()


def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath('../Util'), relative_path)


def get_open_file_path_from_dialog(widget_parent, file_type, root_directory=None):
    _root_directory = RUNNING_DIRECTORY
    if root_directory is not None:
        _root_directory = root_directory
    full_file_name, _file_type = QtWidgets.QFileDialog.getOpenFileName(widget_parent, "选择文件", _root_directory,
                                                                       file_type)
    return full_file_name


def get_open_file_paths_from_dialog(widget_parent, file_type, root_directory=None):
    _root_directory = RUNNING_DIRECTORY
    if root_directory is not None:
        _root_directory = root_directory
    full_file_names, _file_types = QtWidgets.QFileDialog.getOpenFileNames(widget_parent, "选择文件", root_directory,
                                                                          file_type)
    return full_file_names


def get_save_file_path_from_dialog(widget_parent, file_type, root_directory=None):
    _root_directory = RUNNING_DIRECTORY
    if root_directory is not None:
        _root_directory = root_directory
    try:
        full_file_name, _ = QtWidgets.QFileDialog.getSaveFileName(widget_parent, "Save", _root_directory, file_type)
        return full_file_name
    except:
        return None


def get_new_file_path_without_dialog(parent_directory, file_name, file_type):
    i = 1
    while True:
        temp = parent_directory + "/" + file_name + str(i) + file_type
        if os.path.isfile(temp):
            i += 1
            continue
        else:
            return temp


def get_parent_directory(full_file_name):
    dirname = os.path.dirname(full_file_name)
    return dirname


def get_all_file_paths_from_directory(directory):
    full_file_names = []
    if os.path.isdir(directory):
        for root, dirs, files in os.walk(directory):
            full_file_names.append(files)
        full_file_names = full_file_names[0]
        for k, item in enumerate(full_file_names):
            full_file_names[k] = copy.copy(directory + "/" + item)
        return full_file_names
    else:
        return None


def get_stripped_name(full_file_name):
    return QtCore.QFileInfo(full_file_name).fileName()


def get_stripped_name_without_file_type(full_file_name):
    return QtCore.QFileInfo(full_file_name).baseName()


def get_file_type(full_file_name):
    return os.path.splitext(full_file_name)[1]
