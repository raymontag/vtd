vtd - VirusTotal-daemon
=======================

A pythonic daemon which scans a folder all 60 seconds for new files in a specific folder, checks if they are already known to the daemon and submit them to VirusTotal if not. Scan reports are sended via mail and saved to another folder.

Run 'sh configure.sh' first. If it asks for...

Host - Type the host of your SMTP server
Port - Type the port of your SMTP server
Username - Type your AUTH username
Password - Type your AUTH password
From - Type from which mail the notification mails should come from
To - The mail address where the mails should sended to
API-Key - Your VirusTotal API key
DL folder - The folder where your honeypot or whatever download the files
ST folder - The folder where the files and reports should saved to

Warning: This is just a really quick&dirty implementation. Adjust it to your needs.

I'm looking forward to suggestions or merge requests.
