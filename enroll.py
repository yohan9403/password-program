#!/usr/bin/env python3

# CPSC526 Assignment2 Question 1
# ID: 10136488
# PASSLIB library's argon2 function does the salting, then hash the password
# i.e., argon2.hash("password") -> generates salt, then hash the password.
# https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html

import sys
import os
import itertools
from passlib.hash import argon2

def main(argv):

    # arguments check
    if len(sys.argv) != 3:
        exit('Usage: ./enroll.py <id> <password>')

    # set user id and password from user input
    user_id  = sys.argv[1]
    password = sys.argv[2]

    # dont let user use :, since its used as delimiter for user_id and password in password file
    # every other character except ' ' is fine
    if ':' in user_id:
        exit('Dont use ":" in your ID.')

    # check password, need to do 4 checks
    PW_components = ["".join(x) for _, x in itertools.groupby(password, key=str.isdigit)]
    if len(PW_components) == 1:
        # if password is in the dictionary, exit
        if PW_components[0] in open('dictionary.txt').read():
            exit("password cannot be a dictionary word, exiting")

        # if password is just number exit
        if PW_components[0].isnumeric():
            exit("password cannot be just numbers, exiting")

    if len(PW_components) == 2:
        # if password is composed of dictionary word followed by numbers
        if PW_components[0] in open('dictionary.txt').read() and PW_components[1].isnumeric():
            exit("password cannot be composed of dictionary word followed by numbers, exiting")

        # if password is composed of numbers followed by dictionary word
        if PW_components[0].isnumeric() and PW_components[1] in open('dictionary.txt').read():
            exit("password cannot be composed of numbers followed by dictionary word, exiting")


    # if everything is okay for id and password, we can store the user name
    # AND password together in a password file, using argon2 (probably best practice)
    # check if password file exists
    # create a password file otherwise
    if not os.path.exists('pw'):
        f = open('pw', 'a').close()

    # populate hash table from password file to make enrollment process faster
    password_table = {}
    with open('pw', 'r') as password_file:
        for id_hash_pairs in password_file:
            key = id_hash_pairs[:id_hash_pairs.index(':')]
            val = id_hash_pairs[id_hash_pairs.index(':') + 1:].strip('\n')
            password_table[key] = val

    # test to see if password table is generating correctly
    print(password_table)

    # check if user has been enrolled previously,
    # if so, reject request
    if user_id in password_table:
        exit("Rejected.\n")
    # otherwise
    else:
        # create hash to store in password file
        # and open pw file to store userid:correspondinghash
        hash = argon2.hash(password)
        with open('pw', 'a') as password_file:
            password_file.write(user_id + ':' + hash + '\n')
            exit("Accepted.\n")

if __name__ == '__main__':
    main(sys.argv[1:])
