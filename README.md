## Setting up TCP level hints

# Purpose

For proxy and vpn detection the TCP level data has a good signal to noise potential because the infrastructure to supress lower level stack details is more expensive and used less often.

Using this technique we can expose TCP packet analysis to the application level
and build some logic on top of the lower level data.

This requires setting up a passive TCP packet filter on the load balancer node and augmenting the HTTP traffic with additional info.

### Components

- p0f (libpcap based sniffer process)
- haproxy (load balancer)
- SPOA agent (Go process, haproxy middleware)
- configs 

### Architecture details

` TCP -> [p0f] <->  [SPOA] <->  [haproxy]  -> new HTTP headers -> APP`

### Command flow

1. p0f is a passive TCP packet capturing process. It maintains a cache of TCP data for each IP of 30 minutes.

3. p0f opens a local socket to receive requests from the user software

5. SPOA is a process which opens sockets for haproxy requests and queries p0f socket for getting TCP information

7. haproxy on each new connection sends request to SPOA, which asks p0f and returns detailed data

9. haproxy fills new HTTP headers and forwards the augmented HTTP  to the backend
 
 
### Setup Instructions


Build custom p0f with mtu and mss data

    ./build.sh all
    in case it fails, check CRLF, if necessary do:
    dos2unix build.sh


Make sure it starts on startup (change network name to the actual one) or setup a new service which runs on startup:
`sudo p0f -i INTERFACE_NAME -s /var/run/p0f.sock -d`

Build SPOA agent code (`spoa-p0f/main.go`).

Place executable as `/usr/local/bin/spoa-p0f` and setup new service running spoa agent:

    sudo tee /etc/systemd/system/p0f-spoe-agent.service >/dev/null <<'UNIT'
    [Unit]
    Description=p0f SPOE agent
    After=network.target
    
    [Service]
    ExecStart=/usr/local/bin/spoa-p0f
    Restart=on-failure
    User=nobody
    Group=nogroup
    AmbientCapabilities=
    NoNewPrivileges=true
    LimitNOFILE=4096
    
    [Install]
    WantedBy=multi-user.target
    UNIT
    

(Check it works):

        sudo systemctl daemon-reload
        sudo systemctl enable --now p0f-spoe-agent
        systemctl status p0f-spoe-agent --no-pager


The p0f.spop is a schema for haproxy <-> spoa communication.
Copy `p0f.spop` config as `/etc/haproxy/p0f.spop`

Add the following records into haproxy.cfg:

    # inside this block (Public HTTP endpoint):
    # frontend fe_http
    
      filter spoe engine p0f config /etc/haproxy/p0f.spop
    
      # Trigger SPOE once per connection (first HTTP request only)
      http-request send-spoe-group p0f p0f-group if !{ var(sess.p0f.os) -m found }
    
      # Force SPOE while debugging (remove the condition temporarily)
      http-request send-spoe-group p0f p0f-group
    
      # Set headers
      http-request set-header x_tcp_os          %[var(sess.p0f.os)]          if { var(sess.p0f.os) -m found }
      http-request set-header x_tcp_link        %[var(sess.p0f.link)]        if { var(sess.p0f.link) -m found }
      http-request set-header x_tcp_dist        %[var(sess.p0f.dist)]        if { var(sess.p0f.dist) -m found }
      http-request set-header x_tcp_uptime      %[var(sess.p0f.uptime)]      if { var(sess.p0f.uptime) -m found }
      http-request set-header x_tcp_nat         %[var(sess.p0f.nat)]         if { var(sess.p0f.nat) -m found }
      http-request set-header x-tcp-matchq      %[var(sess.p0f.os_match_q)]  if { var(sess.p0f.os_match_q) -m found }
      http-request set-header x-tcp-mtu         %[var(sess.p0f.link_mtu)]         if { var(sess.p0f.link_mtu) -m found }
      http-request set-header x-tcp-mss         %[var(sess.p0f.link_mss)]         if { var(sess.p0f.link_mss) -m found }


Restart haproxy:

`sudo systemctl reload haproxy`

## Troubleshooting

If p0f fails to start, check if it is able to load the p0f.fp file (text file with signatures).
In case of failure, check CRLF and do dos2unix if needed.

If all goes well the HTTP packets coming into the backend app should contain
new headers with prefix x-tcp (or as in the sample cfg file, **X-P0f-**).

When no any new header is found here are the things to check:
- Make sure p0f is running and has an open socket:
`ls -l /var/run/p0f.sock`

- Make sure SPOA is running and has an open socket:
`ss -ltnep | grep ':9000'`

- Make sure haproxy config is valid:
`haproxy -c -f /etc/haproxy/haproxy.cfg`

- SPOA logs:
`sudo journalctl -u p0f-spoe-agent -f`

- haproxy logs:
journalctl -xeu haproxy.service

- optionally p0f logs can be enabled too, for example:
`sudo p0f -i eth0 -o /var/log/p0f.log -u p0f -f /etc/p0f/p0f.fp &`

### Additional info
In the file `/etc/p0f/p0f.fp` there is a list of signatures used to determine heuristics, 
it can be further modified if needed to accomodate specific use cases.




