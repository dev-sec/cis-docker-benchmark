# encoding: utf-8
# frozen_string_literal: true

# Copyright 2016, Patrick Muench
# Copyright 2017, Christoph Hartmann
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Christoph Hartmann
# author: Dominik Richter
# author: Patrick Muench

title 'Docker Daemon Configuration'

# attributes
DAEMON_TLSCACERT = attribute('daemon_tlscacert')
DAEMON_TLSCERT = attribute('daemon_tlscert')
DAEMON_TLSKEY = attribute('daemon_tlskey')
AUTHORIZATION_PLUGIN = attribute('authorization_plugin')
LOG_DRIVER = attribute('log_driver')
LOG_OPTS = attribute('log_opts')
SWARM_MODE = attribute('swarm_mode')
SWARM_MAX_MANAGER_NODES = attribute('swarm_max_manager_nodes')
SWARM_PORT = attribute('swarm_port')
SECCOMP_DEFAULT_PROFILE = attribute('seccomp_default_profile')

# check if docker exists
only_if('docker not found') do
  command('docker').exist?
end

control 'docker-2.1' do
  impact 1.0
  title 'Restrict network traffic between containers'
  desc 'By default, all network traffic is allowed between containers on the same host. If not desired, restrict all the intercontainer communication. Link specific containers together that require inter communication.

  Rationale: By default, unrestricted network traffic is enabled between all containers on the same host. Thus, each container has the potential of reading all packets across the container network on the same host. This might lead to unintended and unwanted disclosure of information to other containers. Hence, restrict the inter container communication.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.1'
  tag 'cis-docker-1.13.0': '2.1'
  tag 'level:1'
  ref 'Docker container networking', url: 'https://docs.docker.com/engine/userguide/networking/'

  describe json('/etc/docker/daemon.json') do
    its(['icc']) { should eq(false) }
  end
end

control 'docker-2.2' do
  impact 1.0
  title 'Set the logging level'
  desc 'Set Docker daemon log level to \'info\'.

  Rationale: Setting up an appropriate log level, configures the Docker daemon to log events that you would want to review later. A ase log level of \'info\' and above would capture all logs except debug logs. Until and unless required, you should not run docker daemon at \'debug\' log level.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.2'
  tag 'cis-docker-1.13.0': '2.2'
  tag 'level:1'
  ref 'Docker daemon', url: 'https://docs.docker.com/engine/reference/commandline/daemon/'

  describe json('/etc/docker/daemon.json') do
    its(['log-level']) { should eq('info') }
  end
end

control 'docker-2.3' do
  impact 1.0
  title 'Allow Docker to make changes to iptables'
  desc 'Iptables are used to set up, maintain, and inspect the tables of IP packet filter rules in the Linux kernel. Allow the Docker daemon to make changes to the iptables.

  Rationale: Docker will never make changes to your system iptables rules if you choose to do so. Docker server would automatically make the needed changes to iptables based on how you choose your networking options for the containers if it is allowed to do so. It is recommended to let Docker server make changes to iptables automatically to avoid networking misconfiguration that might hamper the communication between containers and to the outside world. Additionally, it would save you hassles of updating iptables every time you choose to run the containers or modify networking options.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.3'
  tag 'cis-docker-1.13.0': '2.3'
  tag 'level:1'
  ref 'Understand container communication', url: 'https://docs.docker.com/engine/userguide/networking/default_network/container-communication/'

  describe json('/etc/docker/daemon.json') do
    its(['iptables']) { should eq(true) }
  end
end

control 'docker-2.4' do
  impact 1.0
  title 'Do not use insecure registries'
  desc 'Docker considers a private registry either secure or insecure. By default, registries are considered secure.

  Rationale: A secure registry uses TLS. A copy of registry\'s CA certificate is placed on the Docker host at \'/etc/docker/certs.d/<registry-name>/\' directory. An insecure registry is the one not having either valid registry certificate or is not using TLS. You should not be using any insecure registries in the production environment. Insecure registries can be tampered with leading to possible compromise to your production system. Additionally, If a registry is marked as insecure then \'docker pull\', \'docker push\', and \'docker search\' commands will not result in an error message and the user might be indefinitely working with insecure registries without ever being notified of potential danger.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.4'
  tag 'cis-docker-1.13.0': '2.4'
  tag 'level:1'
  ref 'Insecure registry', url: 'https://docs.docker.com/registry/insecure/'

  describe json('/etc/docker/daemon.json') do
    its(['insecure-registries']) { should be_empty }
  end
end

control 'docker-2.5' do
  impact 1.0
  title 'Do not use the aufs storage driver'
  desc 'Do not use \'aufs\' as storage driver for your Docker instance.

  Rationale: The \'aufs\' storage driver is the oldest storage driver. It is based on a Linux kernel patch-set that is unlikely to be merged into the main Linux kernel. \'aufs\' driver is also known to cause some serious kernel crashes. \'aufs\' just has legacy support from Docker. Most importantly, \'aufs\' is not a supported driver in many Linux distributions using latest Linux kernels.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.5'
  tag 'cis-docker-1.13.0': '2.5'
  tag 'level:1'
  ref 'Docker daemon storage driver options', url: 'https://docs.docker.com/engine/reference/commandline/cli/#daemon-storage-driver-option'
  ref 'Switch from aufs to devicemapper', url: 'http://muehe.org/posts/switching-docker-from-aufs-to-devicemapper/'
  ref 'Deep dive into docker storage drivers', url: 'http://jpetazzo.github.io/assets/2015-03-05-deep-dive-into-docker-storage-drivers.html#1'
  ref 'Docker storage drivers', url: 'https://docs.docker.com/engine/userguide/storagedriver/'

  describe json('/etc/docker/daemon.json') do
    its(['storage-driver']) { should_not eq('aufs') }
  end
end

control 'docker-2.6' do
  impact 1.0
  title 'Configure TLS authentication for Docker daemon'
  desc 'It is possible to make the Docker daemon to listen on a specific IP and port and any other Unix socket other than default Unix socket. Configure TLS authentication to restrict access to Docker daemon via IP and port.

  Rationale: By default, Docker daemon binds to a non-networked Unix socket and runs with \'root\' privileges. If you change the default docker daemon binding to a TCP port or any other Unix socket, anyone with access to that port or socket can have full access to Docker daemon and in turn to the host system. Hence, you should not bind the Docker daemon to another IP/port or a Unix socket. If you must expose the Docker daemon via a network socket, configure TLS authentication for the daemon and Docker Swarm APIs (if using). This would restrict the connections to your Docker daemon over the network to a limited number of clients who could successfully authenticate over TLS.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.6'
  tag 'cis-docker-1.13.0': '2.6'
  tag 'level:1'
  ref 'Protect Docker deamon socket', url: 'https://docs.docker.com/engine/security/https/'

  describe json('/etc/docker/daemon.json') do
    its(['tls']) { should eq(true) }
    its(['tlsverify']) { should eq(true) }
    its(['tlscacert']) { should eq(DAEMON_TLSCACERT) }
    its(['tlscert']) { should eq(DAEMON_TLSCERT) }
    its(['tlskey']) { should eq(DAEMON_TLSKEY) }
  end
end

control 'docker-2.7' do
  impact 1.0
  title 'Set default ulimit as appropriate'
  desc 'Set the default ulimit options as appropriate in your environment.

  Rationale: ulimit provides control over the resources available to the shell and to processes started by it. Setting system resource limits judiciously saves you from many disasters such as a fork bomb. Sometimes, even friendly users and legitimate processes can overuse system resources and in-turn can make the system unusable. Setting default ulimit for the Docker daemon would enforce the ulimit for all container instances. You would not need to setup ulimit for each container instance. However, the default ulimit can be overridden during container runtime, if needed. Hence, to control the system resources, define a default ulimit as needed in your environment.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.7'
  tag 'cis-docker-1.13.0': '2.7'
  tag 'level:1'
  ref 'Docker daemon deafult ulimits', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#default-ulimits'

  describe json('/etc/docker/daemon.json') do
    its(['default-ulimits', 'nproc']) { should eq('1024:2408') }
    its(['default-ulimits', 'nofile']) { should eq('100': '200') }
  end
end

control 'docker-2.8' do
  impact 1.0
  title 'Enable user namespace support'
  desc 'Enable user namespace support in Docker daemon to utilize container user to host user re-mapping. This recommendation is beneficial where containers you are using do not have an explicit container user defined in the container image. If container images that you are using have a pre-defined non-root user, this recommendation may be skipped since this feature is still in its infancy and might give you unpredictable issues and complexities.

  Rationale: The Linux kernel user namespace support in Docker daemon provides additional security for the Docker host system. It allows a container to have a unique range of user and group IDs which are outside the traditional user and group range utilized by the host system. For example, the root user will have expected administrative privilege inside the container but can effectively be mapped to an unprivileged UID on the host system.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.8'
  tag 'cis-docker-1.13.0': '2.8'
  tag 'level:2'
  ref 'User namespeces', url: 'http://man7.org/linux/man-pages/man7/user_namespaces.7.html'
  ref 'Docker daemon configuration', url: 'https://docs.docker.com/engine/reference/commandline/daemon/'
  ref 'Routing out root: user namespaces in docker', url: 'http://events.linuxfoundation.org/sites/events/files/slides/User%20Namespaces%20-%20ContainerCon%202015%20-%2016-9-final_0.pdf'
  ref 'Docker images vanish when using user namespaces ', url: 'https://github.com/docker/docker/issues/21050'

  describe json('/etc/docker/daemon.json') do
    its(['userns-remap']) { should eq('default') }
  end
  describe file('/etc/subuid') do
    it { should exist }
    it { should be_file }
  end
  describe file('/etc/subgid') do
    it { should exist }
    it { should be_file }
  end
end

control 'docker-2.9' do
  impact 1.0
  title 'Confirm default cgroup usage'
  desc 'The --cgroup-parent option allows you to set the default cgroup parent to use for all the containers. If there is no specific use case, this setting should be left at its default.

  Rationale: System administrators typically define cgroups under which containers are supposed to run. Even if cgroups are not explicitly defined by the system administrators, containers run under docker cgroup by default. It is possible to attach to a different cgroup other than that is the default. This usage should be monitored and confirmed. By attaching to a different cgroup than the one that is a default, it is possible to share resources unevenly and thus might starve the host for resources.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.9'
  tag 'cis-docker-1.13.0': '2.9'
  tag 'level:2'
  ref 'Docker daemon configuration', url: 'https://docs.docker.com/engine/reference/commandline/daemon/'

  describe json('/etc/docker/daemon.json') do
    its(['cgroup-parent']) { should eq('docker') }
  end
end

control 'docker-2.10' do
  impact 1.0
  title 'Do not change base device size until needed'
  desc 'In certain circumstances, you might need containers bigger than 10G in size. In these cases, carefully choose the base device size.

  Rationale: The base device size can be increased at daemon restart. Increasing the base device size allows all future images and containers to be of the new base device size. A user can use this option to expand the base device size however shrinking is not permitted. This value affects the system-wide “base” empty filesystem that may already be initialized and inherited by pulled images. Though the file system does not allot the increased size if it is empty, it will use more space for the empty case depending upon the device size. This may cause a denial of service by ending up in file system being over-allocated or full.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.10'
  tag 'cis-docker-1.13.0': '2.10'
  tag 'level:2'
  ref 'Docker daemon storage driver options', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#storage-driver-options'

  describe json('/etc/docker/daemon.json') do
    its(['storage-opts']) { should eq(['dm.basesize=10G']) }
  end
end

control 'docker-2.11' do
  impact 1.0
  title 'Use authorization plugin'
  desc 'Docker’s out-of-the-box authorization model is all or nothing. Any user with permission to access the Docker daemon can run any Docker client command. The same is true for callers using Docker’s remote API to contact the daemon. If you require greater access control, you can create authorization plugins and add them to your Docker daemon configuration. Using an authorization plugin, a Docker administrator can configure granular access policies for managing access to Docker daemon.

  Rationale: Docker’s out-of-the-box authorization model is all or nothing. Any user with permission to access the Docker daemon can run any Docker client command. The same is true for callers using Docker’s remote API to contact the daemon. If you require greater access control, you can create authorization plugins and add them to your Docker daemon configuration. Using an authorization plugin, a Docker administrator can configure granular access policies for managing access to Docker daemon.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.11'
  tag 'cis-docker-1.13.0': '2.11'
  tag 'level:2'
  ref 'Access authorization', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#access-authorization'
  ref 'Auhtorization plugins', url: 'https://docs.docker.com/engine/extend/plugins_authorization/'
  ref 'Twistlock authorization plugin', url: 'https://github.com/twistlock/authz'

  describe json('/etc/docker/daemon.json') do
    its(['authorization-plugins']) { should_not be_empty }
    its(['authorization-plugins']) { should eq([AUTHORIZATION_PLUGIN]) }
  end
end

control 'docker-2.12' do
  impact 1.0
  title 'Configure centralized and remote logging'
  desc 'Docker now supports various log drivers. A preferable way to store logs is the one that supports centralized and remote logging.

  Ratonale: Centralized and remote logging ensures that all important log records are safe despite catastrophic events. Docker now supports various such logging drivers. Use the one that suits your environment the best.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.12'
  tag 'cis-docker-1.13.0': '2.12'
  tag 'level:2'
  ref 'Logging overview', url: 'https://docs.docker.com/engine/admin/logging/overview/'

  describe json('/etc/docker/daemon.json') do
    its(['log-driver']) { should_not be_empty }
    its(['log-driver']) { should eq(LOG_DRIVER) }
    its(['log-opts']) { should include(LOG_OPTS) }
  end
end

control 'docker-2.13' do
  impact 1.0
  title 'Disable operations on legacy registry (v1)'
  desc 'The latest Docker registry is v2. All operations on the legacy registry version (v1) should be restricted.

  Rationale: Docker registry v2 brings in many performance and security improvements over v1. It supports container image provenance and other security features such as image signing and verification. Hence, operations on Docker legacy registry should be restricted.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.13'
  tag 'cis-docker-1.13.0': '2.13'
  tag 'level:1'
  ref 'Docker daemon storage driver options', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#storage-driver-options'
  ref 'Proposal: Provenance step 1 - Transform images for validation and verification', url: 'https://github.com/docker/docker/issues/8093'
  ref 'Proposal: JSON Registry API V2.1', url: 'https://github.com/docker/docker/issues/9015'
  ref 'Registry next generation', url: 'https://github.com/docker/docker-registry/issues/612'
  ref 'Docker Registry HTTP API V2', url: 'https://docs.docker.com/registry/spec/api/'
  ref 'Creating Private Docker Registry 2.0 with Token Authentication Service', url: 'https://the.binbashtheory.com/creating-private-docker-registry-2-0-with-token-authentication-service/'
  ref 'New Tool to Migrate From V1 Registry to Docker Trusted Registry or V2 Open Source Registry', url: 'https://blog.docker.com/2015/07/new-tool-v1-registry-docker-trusted-registry-v2-open-source/'
  ref 'Docker Registry V2', url: 'https://www.slideshare.net/Docker/docker-registry-v2'

  describe json('/etc/docker/daemon.json') do
    its(['disable-legacy-registry']) { should eq(true) }
  end
end

control 'docker-2.14' do
  impact 1.0
  title 'Enable live restore'
  desc 'The \'--live-restore\' enables full support of daemon-less containers in docker. It ensures that docker does not stop containers on shutdown or restore and properly reconnects to the container when restarted.

  Rationale: One of the important security triads is availability. Setting \'--live-restore\' flag in the docker daemon ensures that container execution is not interrupted when the docker daemon is not available. This also means that it is now easier to update and patch the docker daemon without execution downtime.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.14'
  tag 'cis-docker-1.13.0': '2.14'
  tag 'level:1'
  ref 'Add --live-restore flag', url: 'https://github.com/docker/docker/pull/23213'

  describe json('/etc/docker/daemon.json') do
    its(['live-restore']) { should eq(true) }
  end
end

control 'docker-2.15' do
  impact 1.0
  title 'Do not enable swarm mode, if not needed'
  desc 'Do not enable swarm mode on a docker engine instance unless needed.

  Rationale: By default, a Docker engine instance will not listen on any network ports, with all communications with the client coming over the Unix socket. When Docker swarm mode is enabled on a docker engine instance, multiple network ports are opened on the system and made available to other systems on the network for the purposes of cluster management and node communications. Opening network ports on a system increase its attack surface and this should be avoided unless required.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.15'
  tag 'cis-docker-1.13.0': '2.15'
  tag 'level:1'
  ref 'docker swarm init', url: 'https://docs.docker.com/engine/reference/commandline/swarm_init/'

  describe docker.info do
    its('Swarm.LocalNodeState') { should eq SWARM_MODE }
  end
end

control 'docker-2.16' do
  impact 1.0
  title 'Control the number of manager nodes in a swarm'
  desc 'Ensure that the minimum number of required manager nodes is created in a swarm.

  Rationale: Manager nodes within a swarm have control over the swarm and change its configuration modifying security parameters. Having excessive manager nodes could render the swarm more susceptible to compromise. If fault tolerance is not required in the manager nodes, a single node should be elected as a manger. If fault tolerance is required then the smallest practical odd number to achieve the appropriate level of tolerance should be configured.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.16'
  tag 'cis-docker-1.13.0': '2.16'
  tag 'level:1'
  ref 'Manage nodes in a swarm', url: 'https://docs.docker.com/engine/swarm/manage-nodes/'
  ref 'Administer and maintain a swarm of Docker Engines', url: 'https://docs.docker.com/engine/swarm/admin_guide/'

  only_if { SWARM_MODE == 'active' }
  describe docker.info do
    its('Swarm.Managers') { should cmp <= SWARM_MAX_MANAGER_NODES }
  end
end

control 'docker-2.17' do
  impact 1.0
  title 'Bind swarm services to a specific host interface'
  desc 'By default, the docker swarm services will listen to all interfaces on the host, which may not be necessary for the operation of the swarm where the host has multiple network interfaces.

  Rationale: When a swarm is initialized the default value for the --listen-addr flag is 0.0.0.0\': \'2377 which means that the swarm services will listen on all interfaces on the host. If a host has multiple network interfaces this may be undesirable as it may expose the docker swarm services to networks which are not involved in the operation of the swarm. By passing a specific IP address to the --listen-addr, a specific network interface can be specified limiting this exposure.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.17'
  tag 'cis-docker-1.13.0': '2.17'
  tag 'level:1'
  ref 'docker swarm init', url: 'https://docs.docker.com/engine/reference/commandline/swarm_init/'
  ref 'Administer and maintain a swarm of Docker Engines', url: 'https://docs.docker.com/engine/swarm/admin_guide/'

  only_if { SWARM_MODE == 'active' }
  describe port(SWARM_PORT) do
    its('addresses') { should_not include '0.0.0.0' }
    its('addresses') { should_not include '::' }
  end
end

control 'docker-2.18' do
  impact 1.0
  title 'Disable Userland Proxy'
  desc 'The docker daemon starts a userland proxy service for port forwarding whenever a port is exposed. Where hairpin NAT is available, this service is generally superfluous to requirements and can be disabled.

  Rationale: Docker engine provides two mechanisms for forwarding ports from the host to containers, hairpin NAT, and a userland proxy. In most circumstances, the hairpin NAT mode is preferred as it improves performance and makes use of native Linux iptables functionality instead of an additional component. Where hairpin NAT is available, the userland proxy should be disabled on startup to reduce the attack surface of the installation.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '2.18'
  tag 'cis-docker-1.13.0': '2.18'
  tag 'level:1'
  ref 'The docker-proxy', url: 'http://windsock.io/the-docker-proxy/'
  ref 'Disable Userland proxy by default', url: 'https://github.com/docker/docker/issues/14856'
  ref 'overlay networking with userland-proxy disabled prevents port exposure', url: 'https://github.com/moby/moby/issues/22741'
  ref 'Bind container ports to the host', url: 'https://docs.docker.com/engine/userguide/networking/default_network/binding/'

  describe json('/etc/docker/daemon.json') do
    its(['userland-proxy']) { should eq(false) }
  end
  describe processes('dockerd').commands do
    it { should include 'userland-proxy=false' }
  end
end

control 'docker-2.19' do
  impact 1.0
  title 'Encrypt data exchanged between containers on different nodes on the overlay network'
  desc 'Encrypt data exchanged between containers on different nodes on the overlay network.

  Rationale: By default, data exchanged between containers on different nodes on the overlay network is not encrypted. This could potentially expose traffic between the container nodes.'

  tag 'docker'
  tag 'cis-docker-1.13.0': '2.19'
  tag 'level:1'
  ref 'Docker swarm mode overlay network security model', url: 'https://docs.docker.com/engine/userguide/networking/overlay-security-model/'
  ref 'Docker swarm container-container traffic not encrypted when inspecting externally with tcpdump', url: 'https://github.com/moby/moby/issues/24253'

  only_if { SWARM_MODE == 'active' }
  if docker_helper.overlay_networks
    docker_helper.overlay_networks.each do |k, _v|
      describe docker_helper.overlay_networks[k] do
        its(['encrypted']) { should_not eq(nil) }
      end
    end
  else
    describe 'Encrypted overlay networks' do
      skip 'Cannot determine overlay networks'
    end
  end
end

control 'docker-2.20' do
  impact 1.0
  title 'Apply a daemon-wide custom seccomp profile, if needed'
  desc 'You can choose to apply your custom seccomp profile at the daemon-wide level if needed and override Docker\'s default seccomp profile.

  Rationale: A large number of system calls are exposed to every userland process with many of them going unused for the entire lifetime of the process. Most of the applications do not need all the system calls and thus benefit by having a reduced set of available system calls. The reduced set of system calls reduces the total kernel surface exposed to the application and thus improvises application security. You could apply your own custom seccomp profile instead of Docker\'s default seccomp profile. Alternatively, if Docker\'s default profile is good for your environment, you can choose to ignore this recommendation.'

  tag 'docker'
  tag 'cis-docker-1.13.0': '2.20'
  tag 'level:2'
  ref 'daemon: add a flag to override the default seccomp profile', url: 'https://github.com/moby/moby/pull/26276'

  describe json('/etc/docker/daemon.json') do
    its(['seccomp-profile']) { should_not eq(nil) }
    its(['seccomp-profile']) { should eq(SECCOMP_DEFAULT_PROFILE) }
  end
end

control 'docker-2.21' do
  impact 1.0
  title 'Avoid experimental features in production'
  desc 'Avoid experimental features in production.

  Rationale: Experimental is now a runtime docker daemon flag instead of a separate build. Passing --experimental as a runtime flag to the docker daemon, activates experimental features. Experimental is now considered a stable release, but with a couple of features which might not have tested and guaranteed API stability.'

  tag 'docker'
  tag 'cis-docker-1.13.0': '2.21'
  tag 'level:1'
  ref 'Changing the definition of experimental', url: 'https://github.com/moby/moby/issues/26713'
  ref 'Make experimental a runtime flag', url: 'https://github.com/moby/moby/pull/27223'

  describe command('docker version --format \'{{ .Server.Experimental }}\'').stdout.chomp do
    it { should eq('false') }
  end
end

control 'docker-2.22' do
  impact 1.0
  title 'Use Docker\'s secret management commands for managing secrets in a Swarm cluster'
  desc 'Use Docker\'s in-built secret management command.

  Rationale: Docker has various commands for managing secrets in a Swarm cluster. This is the foundation for future secret support in Docker with potential improvements such as Windows support, different backing stores, etc.'

  tag 'docker'
  tag 'cis-docker-1.13.0': '2.22'
  tag 'level:2'
  ref 'Secret Management', url: 'https://github.com/moby/moby/pull/27794'

  only_if { SWARM_MODE == 'active' }
  describe command('docker secret ls -q').stdout.split("\n").length do
    it { should be > 0 }
  end
end

control 'docker-2.23' do
  impact 1.0
  title 'Run swarm manager in auto-lock mode'
  desc 'Run Docker swarm manager in auto-lock mode.

  Rationale: When Docker restarts, both the TLS key used to encrypt communication among swarm nodes, and the key used to encrypt and decrypt Raft logs on disk, are loaded into each manager node\'s memory. You should protect the mutual TLS encryption key and the key used to encrypt and decrypt Raft logs at rest. This protection could be enabled by initializing swarm with --autolock flag. With --autolock enabled, when Docker restarts, you must unlock the swarm first, using a key encryption key generated by Docker when the swarm was initialized.'

  tag 'docker'
  tag 'cis-docker-1.13.0': '2.23'
  tag 'level:1'
  ref 'Initialize a swarm with autolocking enabled', url: 'https://github.com/mistyhacks/docker.github.io/blob/af7dfdba8504f9b102fb31a78cd08a06c33a8975/engine/swarm/swarm_manager_locking.md'

  only_if { SWARM_MODE == 'active' }
  describe command('docker swarm unlock-key -q').stdout.chomp.length do
    it { should be > 0 }
  end
end

control 'docker-2.24' do
  impact 1.0
  title 'Rotate swarm manager auto-lock key periodically'
  desc 'Rotate swarm manager auto-lock key periodically.

  Rationale: Swarm manager auto-lock key is not automatically rotated. You should rotate them periodically as a best practice.

  Audit: Currently, there is no mechanism to find out when the key was last rotated on a swarm manager node. You should check with the system administrator if there is a key rotation record and the keys were rotated at a pre-defined frequency.'

  tag 'docker'
  tag 'cis-docker-1.13.0': '2.24'
  tag 'level:1'
  ref 'Swarm Key rotation', url: 'https://github.com/mistyhacks/docker.github.io/blob/af7dfdba8504f9b102fb31a78cd08a06c33a8975/engine/swarm/swarm_manager_locking.md'
end
