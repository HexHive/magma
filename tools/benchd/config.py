import ctypes
import shlex
import os

MAGMA_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../"))

MAGMA_TARGETS = {
    "libpng16": {
        "bugs": [],
        "programs": [("readpng", "@@")]
    },
    "libtiff4": {
        "bugs": [],
        "programs": [("tiffcp", "-i @@ /dev/null")]
    },
    "libxml2": {
        "bugs": [],
        "programs": [("xmllint", "--valid --oldxml10 --push --memory @@")]
    },
    "poppler": {
        "bugs": [],
        "programs": [("pdftoppm", "-mono -cropbox @@"), ("pdfimages", "@@ /tmp/out")]
    }
}

for root,_,files in os.walk(os.path.join(MAGMA_DIR, "patches", "bugs")):
    # populate MAGMA_TARGETS with bugs based on patch targets
    for patch in files:
        patch_num = int(patch[:patch.index(".patch")])
        with open(os.path.join(root, patch)) as file:
            diff_argv = shlex.split(next(file))
            target = diff_argv[-1].split("/")[2]
            MAGMA_TARGETS[target]["bugs"].append(patch_num)

    # calculate the number of elements in the shared object
    files.sort()
    MAGMA_LENGTH = int(files[-1][:files[-1].index(".patch")]) + 1
    break

# The type of objects stored in the shared memory array
MAGMA_TYPE = (2 * ctypes.c_int)
# The zero initializer for this object
MAGMA_TYPE_INIT = MAGMA_TYPE(*[0, 0])
