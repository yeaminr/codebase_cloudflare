"""
Module to perform operations on the working directory
"""

import os
import shutil
import secrets
import string
import logging
from runner.src import api_constant

logger = logging.getLogger(__name__)

def create_dir() -> str | None:
    """
    Create a new working directory
    Working directory will have a prefix read from api_constant.py
    and will have a random string of 10 characters appended to it

    Returns:
    --------
    str | None: The path to the working directory, None if error
    """
    working_dir = api_constant.WORKING_DIR_PREFIX + "".join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(10)
    )
    while os.path.exists(working_dir):
        working_dir = api_constant.WORKING_DIR_PREFIX + "".join(
            secrets.choice(string.ascii_lowercase + string.digits) for _ in range(10)
        )
    try:
        os.makedirs(working_dir)
    except OSError as e:
        logger.error(
            "Error: Failed to make new working directory. %s - %s.", e.filename, e.strerror)
        return None
    return working_dir


def delete_dir(working_dir: str):
    """
    Delete the provided directory
    Args:
    -----
    working_dir (str): The path to the working directory to delete
    """
    if os.path.exists(working_dir) and working_dir.startswith(api_constant.WORKING_DIR_PREFIX):
        try:
            shutil.rmtree(working_dir)
        except OSError as e:
            logger.error("Error: %s - %s.", e.filename, e.strerror)


def copy_tf_files(src: str, dst: str):
    """
    Copy all terraform files (ending with .tf) from source to destination
    Does not look inside subdirectories

    Args:
    -----
    src (str): The path to the source directory
    dst (str): The path to the destination directory
    """
    if not os.path.exists(dst):
        logger.error("Provided desitnation directory not found: %s", dst)
        raise FileNotFoundError(
            f"Provided destination directory not found: {dst}")
    if not os.path.exists(src):
        logger.error("Provided source directory not found: %s", src)
        raise FileNotFoundError(
            f"Provided source directory not found: {src}")

    for file_name in os.listdir(src):
        source = src + "/" + file_name
        destination = dst + "/" + file_name
        if os.path.isfile(source) and file_name.endswith(".tf"):
            try:
                shutil.copy(source, destination)
                logger.info("Terraform file copied : %s", file_name)
            except OSError as e:
                logger.error("Unable to copy file. %s - %s", e.filename, e.strerror)
                raise OSError(
                    f"Unable to copy file. {e.filename} - {e.strerror}") from e
        else:
            logger.info(
                "Skipping file as is not a terraform configuration: %s", file_name)
