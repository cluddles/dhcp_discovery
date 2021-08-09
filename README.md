When using Pihole for DNS without DHCP, the admin interface only displays clients as IP addresses. Depending on how many devices you have on your network and/or how great your memory is, this may not be the most intuitive thing in the world.

This utility sniffs for DHCP traffic (mainly DHCP requests, but occasionally other packets are also useful), and records IP address and corresponding hostnames in /etc/hosts. For any unnamed devices, we attempt to profile the device (using fingerbank.org) to generate some kind of meaningful simulated hostname.

Pihole will pick up hostnames based on /etc/hosts records and display them in the UI.

Build me: docker build -t cluddles/dhcp_discovery .

Run me: ideally with docker-compose
- Bind to /app/secrets.py, file containing "API_KEY='xxxx'" for Fingerbank
- Bind to /etc/hosts, to access output and feed into Pihole

Dev build/run: docker-compose -f docker-compose.dev.yml up -d [--build]
