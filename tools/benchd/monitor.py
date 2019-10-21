#!/usr/bin/env python3

import os
import sys
import mmap
import ctypes
import posix_ipc
# from _multiprocessing import address_of_buffer
from string import ascii_letters, digits
from time import sleep
from functools import reduce
import argparse

SIZE = 100

class DataCollector:
    def __init__(self, data_source, labels, output_file, delim = "\t",
        headers = True, overwrite = False):
        """
        Creates a DataCollector object which consumes data from a source and
        writes it to a file on a periodic basis.

        data_source: a generator object which yields a list of data-points,
            which are tuples of the form (label_idx, value), where label_idx is
            the index of the label in `labels`, and value is an int.

        labels: a list of strings corresponding to the data-point labels

        output_file: the path to the file where the data will be collected,
            row-by-row, as a timeseries.

        delim: the column-delimiting character to use when writing rows to file.

        headers: indicates whether or not column headers should be written to
            file.
        """
        self._source = data_source
        self._output_file = output_file
        self._labels = labels
        self._delim = delim
        self._headers = headers
        self._overwrite = overwrite;

    def run(self, interval_ms = 5000, count = None):
        """
        Starts the data collection process.

        interval_ms: the duration to wait, in milliseconds, between consecutive
            data samples.

        count: the number of data points to collect. (None = unlimited)
        """
        if not self._overwrite:
            assert not os.path.isfile(self._output_file), \
                "Output file exists."

        with open(self._output_file, "w") as f:
            if self._headers:
                f.write(self._delim.join(["TIME"] + self._labels) + "\n")

            time = 0
            while count is None or count > 0:
                try:
                    dps = next(self._source)
                except StopIteration:
                    break

                assert isinstance(dps, list), \
                    "Object returned by source is not a list."
                assert len(dps) == len(self._labels), \
                    "The number of data points generated does not match \
                    the number of labels."
                assert reduce(lambda x,y: x and y,
                    map(lambda x: isinstance(x, tuple) and x[0] >= 0 and
                        x[0] < len(self._labels) and isinstance(x[1], int),
                        dps),
                    True), \
                    "Some or all data points are not of form (idx, value)."
                

                row = [None] * len(self._labels)
                for dp in dps:
                    row[dp[0]] = str(dp[1])
                row = [str(time)] + row
                f.write(self._delim.join(row) + "\n")

                if count is not None:
                    count -= 1
                time += interval_ms
                sleep(interval_ms / 1000)

valid_chars = frozenset("-_. %s%s" % (ascii_letters, digits))
    
typecode_to_type = {
    'c': ctypes.c_char, 'u': ctypes.c_wchar,
    'b': ctypes.c_byte, 'B': ctypes.c_ubyte,
    'h': ctypes.c_short, 'H': ctypes.c_ushort,
    'i': ctypes.c_int, 'I': ctypes.c_uint,
    'l': ctypes.c_long, 'L': ctypes.c_ulong,
    'f': ctypes.c_float, 'd': ctypes.c_double
}

def address_of_buffer(buf):
    return ctypes.addressof(ctypes.c_char.from_buffer(buf))

class ShmemBufferWrapper(object):
    def __init__(self, tag, size, create=True, force=False):
        # default vals so __del__ doesn't fail if __init__ fails to complete
        self._mem = None
        self._map = None
        self._owner = create
        self.size = size
        
        # assert 0 <= size < sys.maxint
        assert 0 <= size < sys.maxsize
        flag = (0, posix_ipc.O_CREX)[create]
        try:
            self._mem = posix_ipc.SharedMemory(tag, flags=flag, size=size)
        except posix_ipc.ExistentialError:
            if force:
                posix_ipc.unlink_shared_memory(tag)
                self._mem = posix_ipc.SharedMemory(tag, flags=flag, size=size)
            else:
                raise

        self._map = mmap.mmap(self._mem.fd, self._mem.size)
        self._mem.close_fd()
        
    def get_address(self):
        # addr, size = address_of_buffer(self._map)
        # assert size == self.size
        addr = address_of_buffer(self._map)
        return addr
        
    def __del__(self):
        if self._map is not None:
            self._map.close()
        if self._mem is not None and self._owner:
            self._mem.unlink()

def ShmemRawArray(typecode_or_type, size_or_initializer, tag, create=True,
    force=False):

    assert frozenset(tag).issubset(valid_chars)
    if tag[0] != "/":
        tag = "/%s" % (tag,)
    
    type_ = typecode_to_type.get(typecode_or_type, typecode_or_type)
    if isinstance(size_or_initializer, int):
        type_ = type_ * size_or_initializer
    else:
        type_ = type_ * len(size_or_initializer)
        
    buffer = ShmemBufferWrapper(tag, ctypes.sizeof(type_), create=create,
        force=force)
    obj = type_.from_address(buffer.get_address())
    obj._buffer = buffer
    
    if not isinstance(size_or_initializer, int):
        obj.__init__(*size_or_initializer)

    return obj

def arr2gen(arr):
    while True:
        dps = []
        for i in range(0, len(arr) * len(arr[0]), len(arr[0])):
            dps += [(i, arr[i//2][0]), (i + 1, arr[i//2][1])]
        yield dps

def run_monitor(storage, sto_size, output_file, interval=5000, count=17280, force=False):
    labels = [[x+"_R",x+"_T"] for x in (str(x).zfill(3) for x in range(sto_size))]
    labels = [label for pair in labels for label in pair]
    src = arr2gen(ShmemRawArray(2 * ctypes.c_int, sto_size, storage, \
        force=force))
    collector = DataCollector(src, labels, output_file, overwrite=force)
    collector.run(interval_ms=interval, count=count)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("storage",
        help="The name of the memory-mapped object to collect data from.")
    parser.add_argument("output",
        help="The path to the output file where collected data will be \
        written.")
    parser.add_argument("--force", action="store_true",
        help="Overwrite the output file if it exists.")
    parser.add_argument("-i", "--interval", type=int, default=5000,
        help="The duration to wait, in milliseconds, between consecutive data \
        samples.")
    parser.add_argument("-n", "--count", type=int,
        help="The number of data points to collect. For example, to collect 1 \
        hour of data points at an interval of 5000 ms, use --count 720")
    args = parser.parse_args()

    run_monitor(args.storage, SIZE, args.output, args.interval, args.count, args.force)

if __name__ == '__main__':
    main()