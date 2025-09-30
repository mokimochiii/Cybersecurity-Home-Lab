## Lab 1: Sending HTTP Requests with Netcat
use:
```bash
netcat localhost 80 < /tmp/request
```
where localhost is the target server and /tmp/request is the request

in this case /tmp/request contains:
```bash
GET / HTTP/1.1
Host: localhost
```
newlines are carriage returns (\r\n)