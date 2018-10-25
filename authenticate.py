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
        exit("No password file exists yet")

    # check if user credential matches one of the hash in pw
    existing_ids = []
    with open('pw', 'r') as pwtable:
        for line in pwtable:
            existing_id = line[:line.index(':')]
            existing_ids.append(existing_id)


    # check if id exists, if not exit
    if not user_id in existing_ids:
        exit("Access denied.\n")
    # if user id exists, check for password credential
    else:
        hash_elements = []
        index = existing_ids.index(user_id)
        with open('pw', 'r') as pwtable:
            for line in pwtable:
                hash_elements.append(line[line.index(':') + 1:].strip('\n'))

        if argon2.verify(to_hash, hash_elements[index]):
            exit("Access granted.\n")

    exit("Access denied.\n")

#            for hash in line.strip('\n').split(':'):
#                if hash.startswith('$argon2i$'):
#                    if argon2.verify(to_hash, hash):
#                        exit("access granted.\n")

#        exit("access denied.\n")

if __name__ == '__main__':
    main(sys.argv[1:])
