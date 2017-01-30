# Overview

Blocks SSH and allows access only from other nodes running the same charm and
from a configurable whitelist of networks and hosts.

This charm covers a very special use case which came in a customer environment.
In this case, ssh access was only permitted from other OpenStack compute nodes,
so this charm is deployed on all compute nodes.
It may only be useful as a template to implement similar things.

# Usage

This charm is a subordinate charm. It must be attached to a another application.
All nodes of the same application it is attached to will allow ssh amongst each other.

 ```
juju deploy iptables-peer-ssh
juju juju add-relation iptables-peer-ssh <yourapp>
```


## Scale out Usage

Scale the application which this charm is subordinate to.


# Configuration

Make sure you allow access from your control nodes if you need ssh access for
debug purposes.

The 'enforce' setting can be set to false to temporarily disable enforcement of
the firewall rules.


# Troubleshooting

If you lock yourself out from accessing machines via ssh. set enforce to false.
```
juju config iptables-peer-ssh enforce=false
```


## iptables-peer-ssh
  - https://github.com/tbaumann/iptables-peer-ssh
  - https://github.com/tbaumann/iptables-peer-ssh/issues
