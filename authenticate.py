#!/usr/bin/env python3

from passlib.hash import argon2
import sys
import os

def main(argv):
    # arguments check
    if len(sys.argv) != 3:
        exit('Usage: ./authenticate.py <id> <password>')

    # set user id and password from user input
    user_id  = sys.argv[1]
    password = sys.argv[2]

    # check if hash exists
    to_hash = user_id+password
    hash = argon2.hash(to_hash)

    # check if pw exists
    if not os.path.exists('pw'):
        exit("no password file exists yet")

    # check if user credential matches one of the hash in pw
    with open('pw', 'r') as pwtable:
        for line in pwtable:
            for hash in line.strip('\n').split(':'):
                if hash.startswith('$argon2i$'):
                    if argon2.verify(to_hash, hash):
                        exit("access granted.\n")

        exit("access denied.\n")

if __name__ == '__main__':
    main(sys.argv[1:])
