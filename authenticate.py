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

    # check if password file exists
    if not os.path.exists('pw'):
        exit("No password file exists yet")

    # populate hash table from password file to make authentication process faster
    password_table = {}
    with open('pw', 'r') as password_file:
        for id_hash_pairs in password_file:
            key = id_hash_pairs[:id_hash_pairs.index(':')]
            val = id_hash_pairs[id_hash_pairs.index(':') + 1:].strip('\n')
            password_table[key] = val

    # test to see if password_table is generating correctly
    # print(password_table)

    # check if user_id exists in password_table
    # if not, reject
    if user_id not in password_table:
        exit("Access denied.\n")
    # if user exists in the password_table, generate hash using password input
    hash = argon2.hash(password)
    if argon2.verify(password, password_table.get(user_id)):
        exit("Access granted.\n")

    exit("Access denied.\n")

if __name__ == '__main__':
    main(sys.argv[1:])
