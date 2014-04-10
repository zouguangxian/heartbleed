Patrik Karlsson have implemented ssl-heartbleed and commited into svn.nmap.org. you can get it from https://svn.nmap.org/nmap/scripts/ssl-heartbleed.nse. they have a discussion here:
http://seclists.org/nmap-dev/2014/q2/22 .

-----------------------------------------------

get more details from

http://heartbleed.com

Credit to author of `ssltest.py` to http://s3.jspenguin.org/ssltest.py


nmap -p 443 -sC --script ./nmap/heartbleed.nse IP
