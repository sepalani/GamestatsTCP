#! /usr/bin/env python
"""Dummy GameSpy's gamestats database.

Work on both Python2 and Python3.

Usage:
    python -i GamestatsDatabase.py
"""

import os
import sqlite3
import time

from contextlib import closing


GETPDR_SKIP_DATA_ON_ERROR = True


def dict_factory(cursor, row):
    return {
        col[0]: row[idx]
        for idx, col in enumerate(cursor.description)
    }


class PTYPE:
    PD_PRIVATE_RO = 0
    PD_PRIVATE_RW = 1
    PD_PUBLIC_RO = 2
    PD_PUBLIC_RW = 3


class DummyGamestatsDatabase():
    PATH = "data"
    VALID_FILENAME = \
        "abcdefghijklmnopqrstuvwxyz" \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
        "0123456789" \
        "+-_ ()[]"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def get_safe_filename(self, filename):
        """Return a safe filename."""
        return ''.join(chr(c) for c in bytearray(filename)
                       if chr(c) in self.VALID_FILENAME)

    def dummy_get_keydata(self, gamename, key):
        """Dummy get key data."""
        gamedir = os.path.join(self.PATH, self.get_safe_filename(gamename))
        if not os.path.exists(gamedir):
            os.makedirs(gamedir)
        key_file = self.get_safe_filename(key) + ".bin"
        key_filepath = os.path.join(gamedir, key_file)
        with open(key_filepath, 'rb') as f:
            data_blocks = f.read().split(b'\x00')
            if any(block for block in data_blocks[1:]):
                # Data after nul byte?
                pass
            return b"".join([b'\\', key, b'\\', data_blocks[0]])

    def get_data(self, gamename, pid, dindex, ptype, keys, mod):
        """Dummy get data.

        TODO: Handle dindex, kv, pid, ptype.
        """
        data = b''
        for key in keys:
            try:
                key_data = self.dummy_get_keydata(gamename, key)
            except:
                if GETPDR_SKIP_DATA_ON_ERROR:
                    return b""
                continue
            data += key_data
        return 1, data, int(time.time())

    def set_data(self, gamename, pid, dindex, ptype, kv, key_values):
        """Dummy set data.

        TODO: Handle dindex, kv, pid, ptype.
        """
        gamedir = os.path.join(self.PATH, self.get_safe_filename(gamename))
        if not os.path.exists(gamedir):
            os.makedirs(gamedir)
        for key, value in key_values:
            key_file = self.get_safe_filename(key) + ".bin"
            key_filepath = os.path.join(gamedir, key_file)
            if not os.path.exists(key_filepath):
                with open(key_filepath, "wb") as f:
                    f.write(value)
        return 1, int(time.time())


class WiimmfiGamestatsDatabase():
    PATH = "GamestatsDatabase.db"
    DATABASE_TIMEOUT = 5.0

    def __init__(self, path=None, timeout=None):
        self.path = path or self.PATH
        self.timeout = timeout or self.DATABASE_TIMEOUT
        self.conn = sqlite3.connect(self.path, timeout=self.timeout)
        self.conn.row_factory = dict_factory
        self.conn.text_factory = bytes

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def init(self, path=None, timeout=None):
        """Initialize Gamestats database."""
        conn = sqlite3.connect(path or self.PATH,
                               timeout=timeout or self.DATABASE_TIMEOUT)
        c = conn.cursor()

        # Gamestats
        c.execute("CREATE TABLE IF NOT EXISTS gamestats"
                  " (gamename TEXT, pid INT, dindex TEXT, ptype INT,"
                  " data TEXT, mod UNSIGNED BIGINT)")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_storage"
                  " ON gamestats (gamename, pid, dindex)")

        conn.commit()
        conn.close()

    def close(self):
        self.conn.close()

    def parse(self, data):
        ls = data.strip(b'\\').split(b'\\')
        if len(ls) % 2:
            # MUST BE EVEN!
            ls.append(b'')
        return list(zip(ls[0::2], ls[1::2]))

    def set_data(self, gamename, pid, dindex, ptype, kv, key_values):
        with closing(self.conn.cursor()) as cursor:
            if kv:
                success, data, mod = self.get_data(gamename, pid, dindex,
                                                   ptype)
                if success and data:
                    old_key_values = self.parse(data)
                    for k, v in key_values:
                        for i, (old_k, old_v) in enumerate(old_key_values):
                            if k == old_k:
                                old_key_values[i] = (k, v)
                                break
                        else:
                            old_key_values.append((k, v))
                    key_values = old_key_values
            data = b"".join(
                b"\\" + key + b"\\" + value
                for key, value in key_values
            )
            mod = int(time.time())
            try:
                cursor.execute(
                    "INSERT OR REPLACE INTO gamestats VALUES (?,?,?,?,?,?)",
                    (gamename, pid, dindex, ptype, data, mod)
                )
                self.conn.commit()
                return 1, mod
            except:
                return 0, 0

    def get_data(self, gamename, pid, dindex, ptype, keys=None, mod=0):
        with closing(self.conn.cursor()) as cursor:
            cursor.execute(
                "SELECT * FROM gamestats"
                " WHERE gamename = ? AND pid = ? AND dindex = ? AND ptype = ?",
                (gamename, pid, dindex, ptype)
            )
            row = cursor.fetchone()
            if not row:
                return 1, b"", 0
            if keys is None:
                data = row["data"]
            else:
                key_values = self.parse(row["data"])
                data = b"".join(
                    b"\\" + k + b"\\" + v.split(b"\0")[0]
                    for k, v in key_values
                    if k in keys
                )
            return 1 + (mod and row["mod"] < mod), data, row["mod"]


def get_data(gamename, pid, dindex, ptype, keys,
             mod=0, is_wiimmfi=False, from_pid=None):
    pid = int(pid)
    ptype = int(ptype)
    if from_pid is not None and pid != int(from_pid) and \
            PTYPE.PD_PUBLIC_RO != ptype != PTYPE.PD_PUBLIC_RW:
        raise ValueError("Private data")
    if is_wiimmfi:
        with WiimmfiGamestatsDatabase() as db:
            return db.get_data(gamename, pid, dindex, ptype, keys, mod)
    else:
        with DummyGamestatsDatabase() as db:
            return db.get_data(gamename, pid, dindex, ptype, keys, mod)


def set_data(gamename, pid, dindex, ptype, kv, key_values,
             is_wiimmfi=False, from_pid=None):
    pid = int(pid)
    if from_pid is not None and pid != int(from_pid):
        raise ValueError("Data can only be set by its owner")
    ptype = int(ptype)
    kv = int(kv)
    if PTYPE.PD_PUBLIC_RW != ptype != PTYPE.PD_PRIVATE_RW:
        raise ValueError("Read-only data")
    if is_wiimmfi:
        with WiimmfiGamestatsDatabase() as db:
            return db.set_data(gamename, pid, dindex, ptype, kv, key_values)
    else:
        with DummyGamestatsDatabase() as db:
            return db.set_data(gamename, pid, dindex, ptype, kv, key_values)


if __name__ == "__main__":
    with WiimmfiGamestatsDatabase() as db:
        db.init()
