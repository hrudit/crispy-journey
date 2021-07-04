"""
Test student-created utility scripts.

EECS 485 Project 2

Andrew DeOrio <awdeorio@umich.edu>
"""
import os
import subprocess
import sqlite3
import pathlib


def test_executables():
    """Verify insta485run, insta485test, insta485db are executables."""
    assert_is_shell_script("bin/insta485run")
    assert_is_shell_script("bin/insta485test")
    assert_is_shell_script("bin/insta485db")


def test_insta485db_destroy():
    """Verify insta485db destroy removes DB file."""
    subprocess.run(["bin/insta485db", "destroy"], check=True)
    assert not os.path.exists("var/insta485.sqlite3")
    assert not os.path.exists("var/uploads")


def test_insta485db_create():
    """Verify insta485db create populates DB with default data."""
    # Destroy, then create database
    subprocess.run(["bin/insta485db", "destroy"], check=True)
    subprocess.run(["bin/insta485db", "create"], check=True)

    # Verify files were created
    assert os.path.exists("var/insta485.sqlite3")
    assert os.path.exists(
        "var/uploads/5ecde7677b83304132cb2871516ea50032ff7a4f.jpg")
    assert os.path.exists(
        "var/uploads/73ab33bd357c3fd42292487b825880958c595655.jpg")
    assert os.path.exists(
        "var/uploads/122a7d27ca1d7420a1072f695d9290fad4501a41.jpg")
    assert os.path.exists(
        "var/uploads/ad7790405c539894d25ab8dcf0b79eed3341e109.jpg")
    assert os.path.exists(
        "var/uploads/505083b8b56c97429a728b68f31b0b2a089e5113.jpg")
    assert os.path.exists(
        "var/uploads/9887e06812ef434d291e4936417d125cd594b38a.jpg")
    assert os.path.exists(
        "var/uploads/e1a7c5c32973862ee15173b0259e3efdb6a391af.jpg")
    assert os.path.exists(
        "var/uploads/2ec7cf8ae158b3b1f40065abfb33e81143707842.jpg")

    # Connect to the database
    connection = sqlite3.connect("var/insta485.sqlite3")
    connection.execute("PRAGMA foreign_keys = ON")

    # There should be 4 rows in the 'users' table
    cur = connection.execute("SELECT count(*) FROM users")
    num_rows = cur.fetchone()[0]
    assert num_rows == 4


def test_insta485db_reset():
    """Verify insta485db reset does a destroy and a create."""
    # Create a "stale" database file
    dbfile = pathlib.Path("var/insta485.sqlite3")
    dbfile.write_text("this should be overwritten")

    # Reset the database
    subprocess.run(["bin/insta485db", "reset"], check=True)

    # Verify database file was overwritten.  Note that we have to open the file
    # in binary mode because sqlite3 format is not plain text.
    content = dbfile.read_bytes()
    assert b"this should be overwritten" not in content


def test_insta485db_dump():
    """Spot check insta485db dump for a few data points."""
    subprocess.run(["bin/insta485db", "reset"], check=True)
    output = subprocess.run(
        ["bin/insta485db", "dump"],
        check=True, stdout=subprocess.PIPE, universal_newlines=True,
    ).stdout
    assert "awdeorio" in output
    assert "73ab33bd357c3fd42292487b825880958c595655.jpg" in output
    assert "Walking the plank" in output


def assert_is_shell_script(path):
    """Assert path is an executable shell script."""
    assert os.path.isfile(path)
    output = subprocess.run(
        ["file", path],
        check=True, stdout=subprocess.PIPE, universal_newlines=True,
    ).stdout
    assert "shell script" in output
    assert "executable" in output
