# Overview

Blocks SSH and allows access only from other nodes running the same charm and
from a configurable whitelist of networks and hosts.

This charm covers a very special use case which came in a customer environment.
In this case, ssh access was only permitted from other OpenStack compute nodes,
so this charm is deployed on all compute nodes.
It may only be useful as a template to implement similar things.

# Usage

 ```
juju deploy iptables-peer-ssh --to unit
```

This charm is designed to run together with other charms on the same unit.
Running it stand alone makes very little sense.

## Scale out Usage

Add units to all hosts which should be covered by this ssh permission.


# Configuration

Make sure you allow access from your control nodes if you need ssh access for
debug purposes.


## iptables-peer-ssh
  - https://github.com/tbaumann/iptables-peer-ssh
  - https://github.com/tbaumann/iptables-peer-ssh/issues
