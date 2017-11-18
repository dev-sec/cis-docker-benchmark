# encoding: utf-8
# frozen_string_literal: true
#
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
DAEMON_TLSCACERT = attribute(
  'daemon_tlscacert',
  description: 'Trust certs signed only by this CA',
  default: '/etc/docker/ssl/ca.pem'
)

DAEMON_TLSCERT = attribute(
  'daemon_tlscert',
  description: 'Path to TLS certificate file',
  default: '/etc/docker/ssl/server_cert.pem'
)

DAEMON_TLSKEY = attribute(
  'daemon_tlskey',
  description: 'Path to TLS key file',
  default: '/etc/docker/ssl/server_key.pem'
)

AUTHORIZATION_PLUGIN = attribute(
  'authorization_plugin',
  description: 'define authorization plugin to manage access to Docker daemon. cis-docker-benchmark-2.11',
  default: 'authz-broker'
)

LOG_DRIVER = attribute(
  'log_driver',
  description: 'define preferable way to store logs. cis-docker-benchmark-2.12',
  default: 'syslog'
)

LOG_OPTS = attribute(
  'log_opts',
  description: 'define Docker daemon log-opts. cis-docker-benchmark-2.12',
  default: /syslog-address/
)

SWARM_MODE = attribute(
  'swarm_mode',
  description: 'define the swarm mode, `active` or `inactive`',
  default: 'inactive'
)

SWARM_MAX_MANAGER_NODES = attribute(
  'swarm_max_manager_nodes',
  description: 'number of manager nodes in a swarm',
  default: 3
)

SWARM_PORT = attribute(
  'swarm_port',
  description: 'port of the swarm node',
  default: 2377
)

# check if docker exists
only_if do
  command('docker').exist?
end

control 'daemon-2.1' do
  impact 1.0
  title 'Restrict network traffic between containers'
  desc 'By default, all network traffic is allowed between containers on the same host. If not desired, restrict all the intercontainer communication. Link specific containers together that require inter communication.

  Rationale: By default, unrestricted network traffic is enabled between all containers on the same host. Thus, each container has the potential of reading all packets across the container network on the same host. This might lead to unintended and unwanted disclosure of information to other containers. Hence, restrict the inter container communication.'

  tag 'daemon'
  tag 'cis-docker-benchmark-1.12.0:2.1'
  tag 'cis-docker-benchmark-1.13.0:2.1'
  tag 'level:1'
  ref 'Docker container networking', url: 'https://docs.docker.com/engine/userguide/networking/'

  describe json('/etc/docker/daemon.json') do
    its(['icc']) { should eq(false) }
  end
end

control 'daemon-2.2' do
  impact 1.0
  title 'Set the logging level'
  desc 'Set Docker daemon log level to \'info\'.

  Rationale: Setting up an appropriate log level, configures the Docker daemon to log events that you would want to review later. A ase log level of \'info\' and above would capture all logs except debug logs. Until and unless required, you should not run docker daemon at \'debug\' log level.'

  tag 'daemon'
  tag 'cis-docker-benchmark-1.12.0:2.2'
  tag 'cis-docker-benchmark-1.13.0:2.2'
  tag 'level:1'
  ref 'Docker daemon', url: 'https://docs.docker.com/engine/reference/commandline/daemon/'

  describe json('/etc/docker/daemon.json') do
    its(['log-level']) { should eq('info') }
  end
end

control 'daemon-2.3' do
  impact 1.0
  title 'Allow Docker to make changes to iptables'
  desc 'Iptables are used to set up, maintain, and inspect the tables of IP packet filter rules in the Linux kernel. Allow the Docker daemon to make changes to the iptables.

  Rationale: Docker will never make changes to your system iptables rules if you choose to do so. Docker server would automatically make the needed changes to iptables based on how you choose your networking options for the containers if it is allowed to do so. It is recommended to let Docker server make changes to iptables automatically to avoid networking misconfiguration that might hamper the communication between containers and to the outside world. Additionally, it would save you hassles of updating iptables every time you choose to run the containers or modify networking options.'

  tag 'daemon'
  tag 'cis-docker-benchmark-1.12.0:2.3'
  tag 'cis-docker-benchmark-1.13.0:2.3'
  tag 'level:1'
  ref 'Understand container communication', url: 'https://docs.docker.com/engine/userguide/networking/default_network/container-communication/'

  describe json('/etc/docker/daemon.json') do
    its(['iptables']) { should eq(true) }
  end
end

control 'daemon-2.4' do
  impact 1.0
  title 'Do not use insecure registries'
  desc 'Docker considers a private registry either secure or insecure. By default, registries are considered secure.

  Rationale: A secure registry uses TLS. A copy of registry\'s CA certificate is placed on the Docker host at \'/etc/docker/certs.d/<registry-name>/\' directory. An insecure registry is the one not having either valid registry certificate or is not using TLS. You should not be using any insecure registries in the production environment. Insecure registries can be tampered with leading to possible compromise to your production system. Additionally, If a registry is marked as insecure then \'docker pull\', \'docker push\', and \'docker search\' commands will not result in an error message and the user might be indefinitely working with insecure registries without ever being notified of potential danger.'

  tag 'daemon'
  tag 'cis-docker-benchmark-1.12.0:2.4'
  tag 'cis-docker-benchmark-1.13.0:2.4'
  tag 'level:1'
  ref 'Insecure registry', url: 'https://docs.docker.com/registry/insecure/'

  describe json('/etc/docker/daemon.json') do
    its(['insecure-registries']) { should be_empty }
  end
end

control 'daemon-2.5' do
  impact 1.0
  title 'Do not use the aufs storage driver'
  desc 'Do not use \'aufs\' as storage driver for your Docker instance.

  Rationale: The \'aufs\' storage driver is the oldest storage driver. It is based on a Linux kernel patch-set that is unlikely to be merged into the main Linux kernel. \'aufs\' driver is also known to cause some serious kernel crashes. \'aufs\' just has legacy support from Docker. Most importantly, \'aufs\' is not a supported driver in many Linux distributions using latest Linux kernels.'

  tag 'daemon'
  tag 'cis-docker-benchmark-1.12.0:2.5'
  tag 'cis-docker-benchmark-1.13.0:2.5'
  tag 'level:1'
  ref 'Docker daemon storage driver options', url: 'https://docs.docker.com/engine/reference/commandline/cli/#daemon-storage-driver-option'
  ref 'Switch from aufs to devicemapper', url: 'http://muehe.org/posts/switching-docker-from-aufs-to-devicemapper/'
  ref 'Deep dive into docker storage drivers', url: 'http://jpetazzo.github.io/assets/2015-03-05-deep-dive-into-docker-storage-drivers.html#1'
  ref 'Docker storage drivers', url: 'https://docs.docker.com/engine/userguide/storagedriver/'

  describe json('/etc/docker/daemon.json') do
    its(['storage-driver']) { should_not eq('aufs') }
  end
end

control 'daemon-2.6' do
  impact 1.0
  title 'Configure TLS authentication for Docker daemon'
  desc 'It is possible to make the Docker daemon to listen on a specific IP and port and any other Unix socket other than default Unix socket. Configure TLS authentication to restrict access to Docker daemon via IP and port.

  Rationale: By default, Docker daemon binds to a non-networked Unix socket and runs with \'root\' privileges. If you change the default docker daemon binding to a TCP port or any other Unix socket, anyone with access to that port or socket can have full access to Docker daemon and in turn to the host system. Hence, you should not bind the Docker daemon to another IP/port or a Unix socket. If you must expose the Docker daemon via a network socket, configure TLS authentication for the daemon and Docker Swarm APIs (if using). This would restrict the connections to your Docker daemon over the network to a limited number of clients who could successfully authenticate over TLS.'

  tag 'daemon'
  tag 'cis-docker-benchmark-1.12.0:2.6'
  tag 'cis-docker-benchmark-1.13.0:2.6'
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

control 'daemon-2.7' do
  impact 1.0
  title 'Set default ulimit as appropriate'
  desc 'Set the default ulimit options as appropriate in your environment.

  Rationale: ulimit provides control over the resources available to the shell and to processes started by it. Setting system resource limits judiciously saves you from many disasters such as a fork bomb. Sometimes, even friendly users and legitimate processes can overuse system resources and in-turn can make the system unusable. Setting default ulimit for the Docker daemon would enforce the ulimit for all container instances. You would not need to setup ulimit for each container instance. However, the default ulimit can be overridden during container runtime, if needed. Hence, to control the system resources, define a default ulimit as needed in your environment.'

  tag 'daemon'
  tag 'cis-docker-benchmark-1.12.0:2.7'
  tag 'cis-docker-benchmark-1.13.0:2.7'
  tag 'level:1'
  ref 'Docker daemon deafult ulimits', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#default-ulimits'

  describe json('/etc/docker/daemon.json') do
    its(['default-ulimits', 'nproc']) { should eq('1024:2408') }
    its(['default-ulimits', 'nofile']) { should eq('100:200') }
  end
end

control 'daemon-2.8' do
  impact 1.0
  title 'Enable user namespace support'
  desc 'Enable user namespace support in Docker daemon to utilize container user to host user re-mapping. This recommendation is beneficial where containers you are using do not have an explicit container user defined in the container image. If container images that you are using have a pre-defined non-root user, this recommendation may be skipped since this feature is still in its infancy and might give you unpredictable issues and complexities.

  Rationale: The Linux kernel user namespace support in Docker daemon provides additional security for the Docker host system. It allows a container to have a unique range of user and group IDs which are outside the traditional user and group range utilized by the host system. For example, the root user will have expected administrative privilege inside the container but can effectively be mapped to an unprivileged UID on the host system.'

  tag 'daemon'
  tag 'cis-docker-benchmark-1.12.0:2.8'
  tag 'cis-docker-benchmark-1.13.0:2.8'
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

control 'cis-docker-benchmark-2.9' do
  impact 1.0
  title 'Confirm default cgroup usage'
  desc 'The --cgroup-parent option allows you to set the default cgroup parent to use for all the containers. If there is no specific use case, this setting should be left at its default.'

  tag 'daemon'
  tag cis: 'docker:2.9'
  tag level: 2
  ref 'Docker daemon configuration', url: 'https://docs.docker.com/engine/reference/commandline/daemon/'

  describe json('/etc/docker/daemon.json') do
    its(['cgroup-parent']) { should eq('docker') }
  end
end

control 'cis-docker-benchmark-2.10' do
  impact 1.0
  title 'Do not change base device size until needed'
  desc 'In certain circumstances, you might need containers bigger than 10G in size. In these cases, carefully choose the base device size.'

  tag 'daemon'
  tag cis: 'docker:2.10'
  tag level: 2
  ref 'Docker daemon storage driver options', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#storage-driver-options'

  describe json('/etc/docker/daemon.json') do
    its(['storage-opts']) { should eq(['dm.basesize=10G']) }
  end
end

control 'cis-docker-benchmark-2.11' do
  impact 1.0
  title 'Use authorization plugin'
  desc 'Docker’s out-of-the-box authorization model is all or nothing. Any user with permission to access the Docker daemon can run any Docker client command. The same is true for callers using Docker’s remote API to contact the daemon. If you require greater access control, you can create authorization plugins and add them to your Docker daemon configuration. Using an authorization plugin, a Docker administrator can configure granular access policies for managing access to Docker daemon.'

  tag 'daemon'
  tag cis: 'docker:2.11'
  tag level: 2
  ref 'Access authorization', url: 'https://docs.docker.com/engine/reference/commandline/daemon/#access-authorization'
  ref 'Auhtorization plugins', url: 'https://docs.docker.com/engine/extend/plugins_authorization/'
  ref 'Twistlock authorization plugin', url: 'https://github.com/twistlock/authz'

  describe json('/etc/docker/daemon.json') do
    its(['authorization-plugins']) { should_not be_empty }
    its(['authorization-plugins']) { should eq([AUTHORIZATION_PLUGIN]) }
  end
end

control 'cis-docker-benchmark-2.12' do
  impact 1.0
  title 'Configure centralized and remote logging'
  desc 'Docker now supports various log drivers. A preferable way to store logs is the one that supports centralized and remote logging.'

  tag 'daemon'
  tag cis: 'docker:2.12'
  tag level: 2
  ref 'Logging overview', url: 'https://docs.docker.com/engine/admin/logging/overview/'

  describe json('/etc/docker/daemon.json') do
    its(['log-driver']) { should_not be_empty }
    its(['log-driver']) { should eq(LOG_DRIVER) }
    its(['log-opts']) { should include(LOG_OPTS) }
  end
end

control 'cis-docker-benchmark-2.13' do
  impact 1.0
  title 'Disable operations on legacy registry (v1)'
  desc 'The latest Docker registry is v2. All operations on the legacy registry version (v1) should be restricted.'

  tag 'daemon'
  tag cis: 'docker:2.13'
  tag level: 2
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

control 'cis-docker-benchmark-2.14' do
  impact 1.0
  title 'Enable live restore'
  desc 'The \'--live-restore\' enables full support of daemon-less containers in docker. It ensures that docker does not stop containers on shutdown or restore and properly reconnects to the container when restarted.'

  tag 'daemon'
  tag cis: 'docker:2.14'
  tag level: 2
  ref 'Add --live-restore flag', url: 'https://github.com/docker/docker/pull/23213'

  describe json('/etc/docker/daemon.json') do
    its(['live-restore']) { should eq(true) }
  end
end

control 'cis-docker-benchmark-2.15' do
  impact 1.0
  title 'Do not enable swarm mode, if not needed'
  desc 'Do not enable swarm mode on a docker engine instance unless needed.'

  tag 'daemon'
  tag cis: 'docker:2.15'
  tag level: 2
  ref 'docker swarm init', url: 'https://docs.docker.com/engine/reference/commandline/swarm_init/'
  describe docker.info do
    its('Swarm.LocalNodeState') { should eq SWARM_MODE }
  end
end

control 'cis-docker-benchmark-2.16' do
  impact 1.0
  title 'Control the number of manager nodes in a swarm'
  desc 'Ensure that the minimum number of required manager nodes is created in a swarm.'

  tag 'daemon'
  tag cis: 'docker:2.16'
  tag level: 2

  only_if { SWARM_MODE == 'active' }
  describe docker.info do
    its('Swarm.Managers') { should cmp <= SWARM_MAX_MANAGER_NODES }
  end
end

control 'cis-docker-benchmark-2.17' do
  impact 1.0
  title 'Bind swarm services to a specific host interface'

  tag 'daemon'
  tag cis: 'docker:2.17'
  tag level: 2

  only_if { SWARM_MODE == 'active' }
  describe port(SWARM_PORT) do
    its('addresses') { should_not include '0.0.0.0' }
    its('addresses') { should_not include '::' }
  end
end

control 'cis-docker-benchmark-2.18' do
  impact 1.0
  title 'Disable Userland Proxy'

  tag 'daemon'
  tag cis: 'docker:2.18'
  tag level: 2

  describe json('/etc/docker/daemon.json') do
    its(['userland-proxy']) { should eq(false) }
  end
  describe processes('dockerd').commands do
    it { should include 'userland-proxy=false' }
  end
end
