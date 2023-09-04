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
- ./tlsserver -inters 10 -noserver   
- will just generate cert chain in current cert dir and the generate result is in cert dir
  - cert/chains.pem is the certificate chain
  - cert/key.pem      is the entity key 
  - cert/key-ec.pem   is the entity key with encode 
  - cert/root.pem     is the root CA 
- the bin file tlsserver is build on ubuntu 18.04 

# for webpki issue to use
- just do `./tlsserver -inters 10 -domain localhost -port 4432` to start one tls server
- then start one rustls client that use webpki to verify, to connect to this server
- when client not load cert/root.pem, the client will loop verify for long time as the intermidiates count incresase  in webpki 0.22.0 and 0.22.1 
- when client load cert/root.pem, then it will end with encount signatures limit in webpki 0.22.1 quickly  


