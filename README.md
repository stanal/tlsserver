# tlsserver
this code is referenced from https://github.com/alexzorin/poc-cve-2018-16875

# generate certificate chain and start tls server 
args:

- -inters 10  intermidiates certificates count
- -noserver   only generate certificate, not start tls server
- -notgencert use current cert dir, not regenerate
- -domain     DNS in certificate 
- -port       port for tls server to listen on

# eg:
./tlsserver -inters 10 -noserver   
will just generate cert chain in current cert dir 

the bin file tlsserver is build on ubuntu 18.04 
