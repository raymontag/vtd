#!/usr/bin/python2

import argparse
import smtplib
from datetime import date
from hashlib import sha256
from json import dumps
from os import listdir, makedirs
from os.path import expanduser, realpath, isdir, isfile, join
from time import sleep
from shutil import move
from sys import exit

from virus_total_apis import PublicApi

from daemon import Daemon

class App(Daemon):
    def __init__(self, config):
        if not isfile(realpath(expanduser(config))):
            print('Run \'sh configure.sh\' first!')
            exit()
        else:
            with open(realpath(expanduser(config)), 'r') as handler:
                self.host = handler.readline().strip('\n')
                self.port = int(handler.readline().strip('\n'))
                self.username = handler.readline().strip('\n')
                self.password = handler.readline().strip('\n')
                self.from_ = handler.readline().strip('\n')
                self.to = handler.readline().strip('\n')
                self.vt = PublicApi(handler.readline().strip('\n'))
                self.dlfolder = realpath(expanduser(handler.readline().strip('\n')))
                self.stfolder = realpath(expanduser(handler.readline().strip('\n')))
                handler.close()

        Daemon.__init__(self, join(self.stfolder, "pidfile"))

    def run(self):
        open(join(self.stfolder, "known_hashes"), "a").close()
        hash_handler = open(join(self.stfolder, "known_hashes"), "r+")
        hashlist = hash_handler.read().split("\n")
        hashlist = {i[:64]:i[78:] for i in hashlist}

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

                    if hashit.hexdigest() in hashlist.keys():
                        pass # TODO: log already founded file
                    else:
                        hashdigest = hashit.hexdigest()
                        hashlist[hashdigest] = i
                        hash_handler.write(hashdigest+" > "+datestring+"/"+i+"\n")
                        hash_handler.flush()

                        if not isdir(join(self.stfolder, datestring)):
                            makedirs(join(self.stfolder, datestring))

                        move(join(self.dlfolder, i), join(self.stfolder, datestring, i))

                        self.scan(hashdigest, join(self.stfolder, datestring, i))
                        
    def scan(self, hashdigest, filepath):
        while True:
            response = self.vt.get_file_report(hashdigest)
            print(dumps(response, sort_keys=False, indent=4))
            if response["results"]["response_code"] == 1:
                self.send(dumps(response, sort_keys=False, indent=4))
                break # TODO: send, log, rescan after x days
            elif respone["results"]["response_code"] == 0:
                response = self.vt.scan_file(filepath)
                sleep(20)
            else:
                sleep(60)

    def send(self, response):
        msg = """From: %s
To: %s
Subject: Virustotal report

%s""" % (self.from_, self.to, response)
        smtp = smtplib.SMTP(self.host, self.port)
        smtp.starttls()
        smtp.login(self.username, self.password)
        smtp.sendmail(self.from_, self.to, msg)
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", default="./config", help="Path to config file", type=str)
    parser.add_argument("cmd", default=None, help="start|stop", type=str)
    args = parser.parse_args()

    app = App(args.config)

    if args.cmd == "start":
        app.run()
    elif args.cmd == "stop":
        app.stop()
    else:
        print("cmd has to be start or stop.")
