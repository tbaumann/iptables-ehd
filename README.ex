# Overview

Blocks SSH and allows access only from other nodes running the same charm and
from a configurable whitelist of networks and hosts.

This charm covers a very special use case which came in a customer environment.
In this case ssh access was only permitted from other openstack compute nodes,
so this charm is delpoyed on all compute nodes.
It may only be useful as a template to implement similar things.

# Usage

Step by step instructions on using the charm:

juju deploy iptables-peer-ssh --to unit

This charm is designed to run together with other charm on the same unit.
Running it stand alone makes very little sense.

## Scale out Usage

Add units to all hosts which should be covered by this ssh permisson.


# Configuration

Make sure you allow access from your control nodes if you need ssh access for
debug purposes.


## iptables-peer-ssh
  - https://github.com/tbaumann/iptables-peer-ssh
  - https://github.com/tbaumann/iptables-peer-ssh/issues
