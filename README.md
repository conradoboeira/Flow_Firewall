# Flow_Firewall

Firewall tool developed in Python 3.8.6 for a CS class. Monitors packets flowing through host and groups then in flows, allowing the user to set rules for blocking communication. 

Use:

```bash
  sudo python flowall.py <Gateway MAC> <Monitored List>
```
Where Gateway MAC is the MAC address for the host which to forward packets (normally should be the router connect to the internet) and Monitored List is a list of IPs to monitor.

During execution, a user can create a new block rule with the command:

```bash
  deny <Origin IP> <Origin Port> <Destination IP> <Destination Port>
```
