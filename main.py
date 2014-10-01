#!/usr/bin/python2

import argparse
from datetime import date
from hashlib import sha256
from os import listdir, makedirs
from os.path import expanduser, realpath, isdir, isfile, join
from time import sleep
from shutil import move
from sys import exit

from virus_total_apis import PublicApi

from daemon import Daemon

class App(Daemon):
    def __init__(self, pathone, pathtwo, key):
        if not (isdir(pathone) and isdir(pathtwo)):
            print("Both paths need to be a directory that exists!")
            exit(1)

        Daemon.__init__(self, join(pathtwo, "pidfile"))

        self.vt = PublicApi(key)
        self.dlfolder = pathone
        self.stfolder = pathtwo

    def run(self):
        open(join(self.stfolder, "known_hashes"), "a").close()
        hash_handler = open(join(self.stfolder, "known_hashes"), "r+")
        hashlist = hash_handler.read().split("\n")

        while True:
            dlcontent = listdir(self.dlfolder)

            if not dlcontent:
                sleep(60)
                continue

            today = date.today()
            year = today.year
            month = today.month
            day = today.day
            datestring = str(year)+"-"+str(month)+"-"+str(day)

            for i in dlcontent:
                with open(join(self.dlfolder, i), "rb") as h:
                    hashit = sha256()
                    hashit.update(h.read())

                    if hashit.hexdigest() in hashlist:
                        pass # TODO: log already founded file
                    else:
                        hashlist.append(hashit.hexdigest())
                        hash_handler.write(hashlist[-1]+"\n")

                        if not isdir(join(self.stfolder, datestring)):
                            makedirs(join(self.stfolder, datestring))

                        move(join(self.dlfolder, i), join(self.stfolder, datestring, i))
                        
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('pathone', default=None, help="Path to download folder", type=str)
    parser.add_argument('pathtwo', default=None, help="Path to store folder", type=str)
    parser.add_argument('key', default=None, help="API-Key", type=str)
    parser.add_argument('cmd', default=None, help="start|stop", type=str)
    args = parser.parse_args()

    app = App(args.pathone, args.pathtwo, args.key)

    if args.cmd == "start":
        app.run()
    elif args.cmd == "stop":
        app.stop()
    else:
        print("cmd has to be start or stop.")
