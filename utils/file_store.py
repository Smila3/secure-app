# this module provides helper functions for safely working with json files.
# the application uses json files instead of a database, so these helpers make it easier to:
# - create missing files with default contents
# - load json data from disk
# - save updated json data back to disk

import json
from pathlib import Path


def ensure_file_exists(path: Path, default):
    # make sure a json file exists before trying to read from it.
    #
    # parameters:
    # - path: the file path that should exist
    # - default: the default data to write if the file does not exist yet
    #
    # this function also makes sure the parent folder exists.

    # create the parent folder if it does not already exist.
    # parents=True allows nested folders to be created if needed.
    # exist_ok=True avoids errors if the folder is already there.
    path.parent.mkdir(parents=True, exist_ok=True)

    # if the file is missing, create it and write the default json content.
    if not path.exists():
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)


def load_json(path: Path, default):
    # load and return json data from a file.
    #
    # parameters:
    # - path: the json file to read
    # - default: the fallback value to use if the file does not exist
    #   or if its contents cannot be parsed correctly
    #
    # this function first ensures the file exists so the application
    # does not crash when reading a missing file.

    # create the file with default contents if needed.
    ensure_file_exists(path, default)

    # open the file and try to parse the json data inside it.
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            # if the file exists but contains invalid json,
            # return the provided default instead of crashing.
            return default


def save_json(path: Path, data):
    # save python data to a json file.
    #
    # parameters:
    # - path: the final file path to save to
    # - data: the python object that should be written as json
    #
    # this function writes to a temporary file first and then replaces
    # the original file. this is safer than writing directly to the target
    # file because it reduces the chance of leaving a partially written file
    # if something goes wrong during the save.

    # make sure the parent folder exists before writing.
    path.parent.mkdir(parents=True, exist_ok=True)

    # create a temporary file path based on the target file path.
    # for example, users.json becomes users.json.tmp
    temp_path = path.with_suffix(path.suffix + ".tmp")

    # write the json data to the temporary file.
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    # replace the original file with the temporary file.
    # this makes the save operation more reliable and more atomic.
    temp_path.replace(path)