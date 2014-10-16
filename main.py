#!/usr/bin/python2

import argparse
import logging
import smtplib
from datetime import date, datetime
from hashlib import sha256
from json import dumps
from os import listdir, makedirs, remove, stat
from os.path import expanduser, realpath, isdir, isfile, join
from time import sleep
from shutil import move
from sys import exit

from virus_total_apis import PublicApi

from daemon import Daemon

class App(Daemon):
    def __init__(self, config, log):
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
        logging.basicConfig(filename=realpath(expanduser(log)), 
                            format='%(asctime)s %(message)s', 
                            datefmt='%m/%d/%Y %I:%M:%S %p',
                            level=logging.INFO)

    def run(self):
        # Touch known_hashes
        if not isdir(self.stfolder):
            makedirs(self.stfolder)
        open(join(self.stfolder, "known_hashes"), "a").close()
        # Read out known_hashes
        hash_handler = open(join(self.stfolder, "known_hashes"), "r+")
        hashlist = hash_handler.read().split("\n")
        hashlist = {i[:64]:i[67:] for i in hashlist}

        while True:
            dlcontent = listdir(self.dlfolder)

            # Rescan all 60 seconds for new files
            if not dlcontent:
                sleep(60)
                continue

            today = date.today()
            year = today.year
            month = today.month
            day = today.day
            datestring = str(year)+"-"+str(month)+"-"+str(day)

            for i in dlcontent:
                # Check if download of file hash finished
                size = stat(join(self.dlfolder, i)).st_size
                sleep(1)
                if stat(join(self.dlfolder, i)).st_size != size:
                    continue

                with open(join(self.dlfolder, i), "rb") as h:
                    # Hash file in dl folder and look if it's known
                    hashit = sha256()
                    hashit.update(h.read())

                    if hashit.hexdigest() in hashlist.keys():
                        # Just remove already known files
                        logging.info("Found already known file "+hashlist[hashit.hexdigest()])
                        remove(join(self.dlfolder, i))
                    else:
                        # Save and scan unknown files and remember the hash
                        hashdigest = hashit.hexdigest()
                        hashlist[hashdigest] = join(datestring, i)
                        hash_handler.write(hashdigest+" > "+join(datestring, i)+"\n")
                        hash_handler.flush()

                        if not isdir(join(self.stfolder, datestring)):
                            makedirs(join(self.stfolder, datestring))

                        move(join(self.dlfolder, i), join(self.stfolder, datestring, i))

                        response = self.scan(hashdigest, join(self.stfolder, datestring, i), today)

                        if not isdir(join(self.stfolder, "reports", datestring)):
                            makedirs(join(self.stfolder, "reports", datestring))

                        open(join(self.stfolder, "reports", datestring, i), "a").close()
                        with open(join(self.stfolder, "reports", datestring, i), "r+") as report:
                            report.write(dumps(response, sort_keys=False, indent=4))
                            report.flush()
                        
    def scan(self, hashdigest, filepath, today):
        scan_flag = True
        while True:
            # First look if file is known to VirusTotal
            response = self.vt.get_file_report(hashdigest)
            if response["response_code"] == 204:
                logging.info("Submission limit reached. I'll sleep for 60 seconds")
                sleep(60)
            elif response["results"]["response_code"] == 1:
                # Rescan needed?
                #scan_date = datetime.strptime(response["results"]["scan_date"][:10],
                                              #"%Y-%m-%d")
                #if abs((today-scan_date).days) >= 30:
                    #self.vt.rescan_file(hashdigest)
                    #continue

                # Send report for unknown file
                msg = """From: %s
To: %s
Subject: Virustotal report

%s""" % (self.from_, self.to, dumps(response, sort_keys=False, indent=4))

                self.send(msg)
                logging.info("Sent report for "+filepath)
                return response
            else:
                # Submit the unknown file
                if scan_flag:
                    response = self.vt.scan_file(filepath)
                    msg = """From: %s
To: %s
Subject: Virustotal submit

Submitted unknown file %s with hash %s for scan.

%s""" % (self.from_, self.to, filepath, hashdigest, dumps(response, sort_keys=False, indent=4))

                    self.send(msg)
                    logging.info("Submitted unknown file "+filepath+" with hash "+hashdigest+" for scan")
                    logging.info("I will sleep know for 60 seconds and try to receive the result after that")
                    sleep(60)
                    scan_flag = False
                else:
                    logging.info("Scan seems not finished. Will sleep for another 30 seconds")
                    sleep(30)

    def send(self, msg):
        smtp = smtplib.SMTP(self.host, self.port)
        smtp.starttls()
        smtp.login(self.username, self.password)
        smtp.sendmail(self.from_, self.to, msg)
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", default="./config", help="Path to config file", type=str)
    parser.add_argument("-l", "--logpath", default="./vtd.log", help="Path to logfile", type=str)
    parser.add_argument("cmd", default=None, help="start|stop|foreground", type=str)
    args = parser.parse_args()

    app = App(args.config, args.logpath)

    if args.cmd == "start":
        app.start()
    elif args.cmd == "stop":
        app.stop()
    elif args.cmd == "foreground":
        app.run()
    else:
        print("cmd has to be start or stop.")
