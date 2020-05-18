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

# The type of objects stored in the shared memory array
MAGMA_TYPE = (2 * ctypes.c_long)
# The zero initializer for this object
MAGMA_TYPE_INIT = MAGMA_TYPE(*[0, 0])
