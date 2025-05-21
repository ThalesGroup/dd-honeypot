### Multiple public IPs
It is possible adding multiple public IPs to an instance. Each IP can use a set of ports, mapped to different honeypots. If for example you want to have more than one http honeypot and run them on port 80, you can map each IP with port 80 to a different honeypot. 

If you are using AWS each of the public IPs can be mapped to a private IP. The private IPs can be used to map container ports to public ports.

```sh
docker run   
  -v /data/honeypot:/data/honeypot \
  -p 10.0.0.1:80:8001  10.0.0.2:80:8002 \
  ghcr.io/thalesgroup/dd-honeypot
docker logs -f dd-honeypot
```
In this example there are two private ips, which are mapped to two different public IPs. The container ports are mapped to the private IPs, and the result is that port 80 on the public IPs is mapped to port 8001 and 8002 on the container.
