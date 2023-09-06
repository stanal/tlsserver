
sudo rm -f /usr/local/share/ca-certificates/root2.crt
sudo update-ca-certificates --fresh
sudo cp cert/root.pem /usr/local/share/ca-certificates/root2.crt
sudo update-ca-certificates
