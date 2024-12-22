import os
import shutil
import pytest
from runner.src import working_dir


# Tests
def test_create_dir(monkeypatch) -> None:
    # Success case 
    monkeypatch.setattr(os, "makedirs", os_makedirs_mock)
    assert working_dir.create_dir() != None

    # Error case - OSError
    monkeypatch.setattr(os, "makedirs", os_makedirs_os_error_mock)
    assert working_dir.create_dir() == None



def test_delete_dir(monkeypatch) -> None:
    # Success case
    monkeypatch.setattr(os.path, "exists", os_path_exists_mock)
    monkeypatch.setattr(shutil, "rmtree", shutil_rmtree_mock)
    working_dir.delete_dir("workingdir_path")

    # Error case - OSError
    working_dir.delete_dir("workingdir_path_os_error")

def test_copy_tf_files(monkeypatch) -> None:
    # Success case
    monkeypatch.setattr(os.path, "exists", os_path_exists_mock)
    monkeypatch.setattr(os, "listdir", os_listdir_mock)
    monkeypatch.setattr(os.path, "isfile", os_isfile_mock)
    monkeypatch.setattr(shutil, "copy", shutil_copy_mock)
    working_dir.copy_tf_files("src", "dst")
    
    # Error - Invalid source
    with pytest.raises(FileNotFoundError):
        working_dir.copy_tf_files("invalid_src", "dst")

    # Error - Invalid destination
    with pytest.raises(FileNotFoundError):
        working_dir.copy_tf_files("src", "invalid_dst")

    # Error - OSError in shutil.copy
    with pytest.raises(OSError):
        working_dir.copy_tf_files("os_error_src", "dst")


# Mocks
def os_makedirs_mock(name):
    return

def os_makedirs_os_error_mock(name):
    raise OSError()

def os_path_exists_mock(name):
    if name == "workingdir_path" or name == "src" or name == "dst":
        return True
    return False

def shutil_rmtree_mock(name):
    if name == "workingdir_path_os_error":
        raise OSError()
    return

def os_listdir_mock(name):
    return ["file1.tf", "file2.tf", "file3.txt"]

def os_isfile_mock(name):
    if name == "src/file1.tf" or name == "src/file2.tf":
        return True
    return False

def shutil_copy_mock(src, dst):
    if src == "os_error_src/file1.tf":
        raise OSError(2, 'unable_to_copy', src)
    return