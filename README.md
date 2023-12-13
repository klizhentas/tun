# tun

This is a mini program that creates virtual IP using tun device and gvisor's user space stack.

Here is how it works:

client <-> tun <-> gvisor userspace TCP/IP stack <-> local webserver

Here is how to use it on MacOS:

```bash
make
# Will create a tun device utun5
sudo ./build/tun
# In a separate tab: bring up virtual device and routing rule that forwards all requests
# to any ip in subnet 10.0.0.1/24 to this utun5 device
sudo make tunup
# In a separate tab, spin up a web server using python
python3 -m http.server
# In a separate tab: hit the webserver via virtual IP
curl http://10.1.0.2:8000 -vvv
# Also works
curl http://10.1.0.3:8000 -vvv
```
