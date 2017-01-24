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
import time


@when_not('iptables-peer-ssh.installed')
def install_iptables_peer_ssh():
    set_state('iptables-peer-ssh.installed')


@when_any('host-system.available', 'host-system.connected')
@when('iptables-peer-ssh.installed')
@when_not('iptables.started')
def setup_iptables():
    status_set('maintenance', 'Setting up IPTables')
    ipset_create('ssh-peers', 'hash:ip')
    ipset_create('ssh-allow-hosts', 'hash:ip')
    ipset_create('ssh-allow-networks', 'hash:net')
    call('iptables -A INPUT -p tcp --dport ssh -m set --match-set ssh-peers src -j ACCEPT', shell=True)
    call('iptables -A INPUT -p tcp --dport ssh -m set --match-set ssh-allow-hosts src -j ACCEPT', shell=True)
    call('iptables -A INPUT -p tcp --dport ssh -m set --match-set ssh-allow-networks src -j ACCEPT', shell=True)
    call('iptables -A INPUT -p tcp --dport ssh -j DROP', shell=True)  # Drop the rest
    status_set('active', 'Ready')
    set_state('iptables.started')


@hook('stop')
def stop_iptables():
    status_set('maintenance', 'Stopping IPTables')
    call('iptables -D INPUT -p tcp --dport ssh -m set --match-set ssh-peers src -j ACCEPT', shell=True)
    call('iptables -D INPUT -p tcp --dport ssh -m set --match-set ssh-allow-hosts src -j ACCEPT', shell=True)
    call('iptables -D INPUT -p tcp --dport ssh -m set --match-set ssh-allow-networks src -j ACCEPT', shell=True)
    call('iptables -D INPUT -p tcp --dport ssh -j DROP', shell=True)  # Drop the rest
    ipset_destroy('ssh-peers')
    ipset_destroy('ssh-allow-hosts')
    ipset_destroy('ssh-allow-networks')
    remove_state('iptables.started')
    status_set('maintenance', 'Stopped')


@hook('upgrade-charm')
def upgrade_charm():
    stop_iptables()
    setup_iptables()


@when('ssh-peers.joined ')
def connected(peers):
    log("ssh-peers.joined")
    if not is_state('iptables.started'):
        setup_iptables()
    hosts = peers.units()
    if data_changed('ssh-peers', hosts):
        ipset_update('ssh-peers', hosts)


@when('ssh-peers.departed')
def departed(peers):
    log("ssh-peers.departed")
    if not is_state('iptables.started'):
        setup_iptables()
    hosts = peers.units()
    if data_changed('ssh-peers', hosts):
        ipset_update('ssh-peers', hosts)


@when('config.changed.ssh-allow-hosts')
def ssh_allow_hosts_changed():
    if not is_state('iptables.started'):
        setup_iptables()
    config = hookenv.config()
    hosts = config['ssh-allow-hosts'].split()
    if data_changed('ssh-allow-hosts', hosts):
        ipset_update('ssh-allow-hosts', hosts)


@when('config.changed.ssh-allow-networks')
def ssh_allow_networks_changed():
    if not is_state('iptables.started'):
        setup_iptables()
    config = hookenv.config()
    hosts = config['ssh-allow-networks'].split()
    if data_changed('ssh-allow-networks', hosts):
        ipset_update('ssh-allow-networks', hosts)


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
