Build me: docker build -t cluddles/dhcp_discovery .

Run me: ideally with docker-compose
- Bind to /app/secrets.py, file containing "API_KEY='xxxx'" for Fingerbank
- Bind to /etc/hosts, to access output and feed into Pihole

Dev build/run: docker-compose -f docker-compose.dev.yml up -d [--build]
