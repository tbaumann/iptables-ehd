from charms.reactive import (
    when,
    when_not,
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
from charms.reactive.helpers import data_changed
from subprocess import call


@when_not('iptables-peer-ssh.installed')
def install_iptables_peer_ssh():
    set_state('iptables-peer-ssh.installed')


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

    # call('iptables -A INPUT -p tcp --dport ssh -j ACCEPT', shell=True)  # Drop the rest
    status_set('active', 'Ready')
    set_state('iptables.started')


@hook('stop')
def stop_iptables():
    status_set('maintenance', 'Stopping IPTables')
    call('iptables -D INPUT -p tcp --dport ssh -m set --match-set ssh-peers src -j ACCEPT', shell=True)
    call('iptables -D INPUT -p tcp --dport ssh -m set --match-set ssh-allow-hosts src -j ACCEPT', shell=True)
    call('iptables -D INPUT -p tcp --dport ssh -m set --match-set ssh-allow-networks src -j ACCEPT', shell=True)
    call('iptables -D INPUT -p tcp --dport ssh -j ACCEPT', shell=True)  # Drop the rest
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
    hosts = peers.units()
    if data_changed('ssh-peers', hosts):
        ipset_update('ssh-peers', hosts)
    remove_state('ssh-peers.joined')


@when('ssh-peers.departed')
def departed(peers):
    hosts = peers.units()
    if data_changed('ssh-peers', hosts):
        ipset_update('ssh-peers', hosts)
    remove_state('ssh-peers.departed')


@when('config.changed.ssh-allow-hosts')
def ssh_allow_hosts_changed():
    config = hookenv.config()
    hosts = config['ssh-allow-hosts'].split()
    if data_changed('ssh-allow-hosts', hosts):
        ipset_update('ssh-allow-hosts', hosts)


@when('config.changed.ssh-allow-networks')
def ssh_allow_networks_changed():
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
