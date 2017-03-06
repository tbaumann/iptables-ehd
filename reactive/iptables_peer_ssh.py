from charms.reactive import (
    when,
    when_not,
    when_any,
    set_state,
    remove_state,
    RelationBase,
    hook
)
from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import (
    related_units,
    local_unit,
    relation_ids,
    relation_get,
    log,
    status_set,
    config,
    in_relation_hook
)
from charms.reactive.helpers import data_changed, is_state
from subprocess import call
from charmhelpers.contrib.network.ip import get_iface_addr
from charmhelpers.contrib.network.ip import is_address_in_network
from netifaces import interfaces
import time


@when_not('iptables-peer-ssh.installed')
def install_iptables_peer_ssh():
    set_state('iptables-peer-ssh.installed')


@when_any('host-system.available', 'host-system.connected')
@when('iptables-peer-ssh.installed')
@when_not('iptables.started')
def iptables_start():
    log('Starting firewall')
    status_set('maintenance', 'Setting up IPTables')
    ipset_create('ssh-peers', 'hash:ip')
    ipset_create('ssh-allow-hosts', 'hash:ip')
    ipset_create('ssh-allow-networks', 'hash:net')

    write_ssh_peers()
    ssh_allow_hosts_changed()
    ssh_allow_networks_changed()

    status_set('active', 'Ready')
    set_state('iptables.started')
    check_enforce()


@when_not('enforcing')
@when('enforce')
def enforce():
    log('Enforcing rules')
    call('iptables -A INPUT -p tcp --dport ssh -m set --match-set ssh-peers src -j ACCEPT', shell=True)
    call('iptables -A INPUT -p tcp --dport ssh -m set --match-set ssh-allow-hosts src -j ACCEPT', shell=True)
    call('iptables -A INPUT -p tcp --dport ssh -m set --match-set ssh-allow-networks src -j ACCEPT', shell=True)
    call('iptables -A INPUT -p tcp --dport ssh -j DROP', shell=True)  # Drop the rest
    set_state('enforcing')


@hook('stop')
def iptables_stop():
    log('Stopping firewall')
    status_set('maintenance', 'Stopping IPTables')
    if is_state('enforcing'):
        not_enforce()
    ipset_destroy('ssh-peers')
    ipset_destroy('ssh-allow-hosts')
    ipset_destroy('ssh-allow-networks')
    remove_state('iptables.started')
    status_set('maintenance', 'Stopped')


@when('enforcing')
@when_not('enforce')
def not_enforce():
    log('Stop enforcing rules')
    call('iptables -D INPUT -p tcp --dport ssh -m set --match-set ssh-peers src -j ACCEPT', shell=True)
    call('iptables -D INPUT -p tcp --dport ssh -m set --match-set ssh-allow-hosts src -j ACCEPT', shell=True)
    call('iptables -D INPUT -p tcp --dport ssh -m set --match-set ssh-allow-networks src -j ACCEPT', shell=True)
    call('iptables --policy INPUT DROP', shell=True)  # Default INPUT policy DROP
    remove_state('enforcing')


@hook('upgrade-charm')
def upgrade_charm():
    iptables_stop()
    iptables_start()


def get_all_addresses():
    addresses = []
    for iface in interfaces():
        if not iface == 'lo':
            for addr in get_iface_addr(iface=iface, inc_aliases=True, fatal=False) or []:
                addresses.append(addr)
    return addresses


def get_all_remote_addresses(peers):
    addresses = []
    for conv in peers.conversations():
        remote_addresses = conv.get_remote('addresses')
        if remote_addresses is None:
            continue
        for addr in str(remote_addresses.split(" ")):
            addresses.append(addr)
    return addresses


@when('ssh-peers.joined')
def connected(peers):
    log("ssh-peers.joined")
    config = hookenv.config()
    addresses = get_all_addresses()
    peers.set_remote('addresses', ' '.join(addresses))
    if is_state('iptables.started'):
        hosts = get_ssh_peers()
        if data_changed('ssh-peers', hosts):
            ipset_update('ssh-peers', hosts)


@when('ssh-peers.departed')
def departed(peers):
    log("ssh-peers.departed")
    if is_state('iptables.started'):
        hosts = get_ssh_peers()
        if data_changed('ssh-peers', hosts):
            ipset_update('ssh-peers', hosts)


@when('config.changed.ssh-allow-hosts')
def ssh_allow_hosts_changed():
    if is_state('iptables.started'):
        config = hookenv.config()
        hosts = config['ssh-allow-hosts'].split()
        if data_changed('ssh-allow-hosts', hosts):
            ipset_update('ssh-allow-hosts', hosts)


@when('config.changed.ssh-allow-networks')
def ssh_allow_networks_changed():
    if is_state('iptables.started'):
        config = hookenv.config()
        hosts = config['ssh-allow-networks'].split()
        if data_changed('ssh-allow-networks', hosts):
            ipset_update('ssh-allow-networks', hosts)


@when('config.changed.enforce')
def change_enforce():
    check_enforce()


@when('config.changed.use-private-addresses')
def change_use_private():
    hosts = get_ssh_peers()
    ipset_update('ssh-peers', hosts)


@when('config.changed.filter-peers-by-networks')
def change_use_private():
    hosts = get_ssh_peers()
    ipset_update('ssh-peers', hosts)


def check_enforce():
    config = hookenv.config()
    if config['enforce']:
        set_state('enforce')
    else:
        remove_state('enforce')


def ipset_create(name, type):
    call(['ipset', 'create',  name, type])
    call(['ipset', 'create',  name + '-tmp', type])


def ipset_destroy(name):
    call(['ipset', 'destroy',  name])
    call(['ipset', 'destroy',  name + '-tmp'])


def ipset_update(name, hosts):
    log("Updating {} ipset".format(name))
    tmpname = name + '-tmp'
    call(['ipset', 'flush', tmpname])
    for host in hosts:
        log("Adding {} to ipset {}".format(host, tmpname))
        call(['ipset', 'add', tmpname, host])
    call(['ipset', 'swap', tmpname, name])
    call(['ipset', 'flush', tmpname])
    log("swapped ipsed {}".format(name))


def get_ssh_peers():
    hosts = []
    config = hookenv.config()
    for rel_id in relation_ids('ssh-peers'):
        for unit in related_units(rel_id):
            if config['use-private-addresses']:
                hosts.append(relation_get('private-address', unit, rel_id))
            else:
                addresses = relation_get('addresses', unit, rel_id)
                if addresses is None:
                    continue
                for addr in str(addresses.split(" ")):
                    hosts.append(addr)
    filtered_networks = get_filter_peers_by_networks(config)
    if filtered_networks:
        hosts = list(filter(lambda addr: is_filtered(addr, filtered_networks), hosts))
    return hosts


def get_filter_peers_by_networks(config):
    return config['filter-peers-by-networks'].split()


def is_filtered(address, networks):
    found = False
    for net in networks:
        if is_address_in_network(net, address):
            found = True
            break
    return found


def write_ssh_peers():
    hosts = get_ssh_peers()
    if data_changed('ssh-peers', hosts):
        ipset_update('ssh-peers', hosts)
