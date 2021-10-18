# CIS Docker Benchmark - InSpec Profile

[![Build Status](http://img.shields.io/travis/dev-sec/cis-docker-benchmark.svg)][1]
[![Supermarket](https://img.shields.io/badge/InSpec%20Profile-CIS%20Docker%20Benchmark-brightgreen.svg)](https://supermarket.chef.io/tools/cis-docker-benchmark)
[![Gitter Chat](https://badges.gitter.im/Join%20Chat.svg)][2]

## Description

This [InSpec](https://github.com/chef/inspec) compliance profile implement the [CIS Docker 1.13.0 Benchmark](https://downloads.cisecurity.org/) in an automated way to provide security best-practice tests around Docker daemon and containers in a production environment.

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Requirements

* at least [InSpec](http://inspec.io/) version 2.3.23
* Docker 1.13+

### Platform

* Debian 8
* Ubuntu 16.04
* CentOS 7

## Attributes

We use a yml attribute file to steer the configuration, the following options are available:

* `trusted_user: vagrant`
  define trusted user to control Docker daemon.
* `authorization_plugin: authz-broker`
  define authorization plugin to manage access to Docker daemon.
* `log_driver: syslog`
  define preferable way to store logs.
* `log_opts: /syslog-address/`
  define Docker daemon log-opts.
* `registry_cert_path: /etc/docker/certs.d`
  directory contains various Docker registry directories.
* `registry_name: /etc/docker/certs.d/registry_hostname:port`
  directory contain certificate certain Docker registry.
* `registry_ca_file: /etc/docker/certs.d/registry_hostname:port/ca.crt`
  certificate file for a certain Docker registry certificate files.
* `container_user: vagrant`
  define user within containers.
* `app_armor_profile: docker-default`
  define apparmor profile for Docker containers.
* `selinux_profile: /label\:level\:s0-s0\:c1023/`
  define SELinux profile for Docker containers.
* `container_capadd: null`
  define needed capabilities for containers. example: `container_capadd: NET_ADMIN,SYS_ADMIN`
* `managable_container_number: 25`
  keep number of containers on a host to a manageable total.
* `daemon_tlscacert : /etc/docker/ssl/ca.pem`
  configure the certificate authority.
* `daemon_tlscert: /etc/docker/ssl/server_cert.pem`
  configure the server certificate.
* `daemon_tlskey: /etc/docker/ssl/server_key.pem`
  configure the server key.
* `swarm_mode: inactive`
  configure the swarm mode.
* `swarm_max_manager_nodes: 3`
  configure the maximum number of swarm leaders.
* `swarm_port: 2377`
  configure the swarm port.
* `benchmark_version`
  to execute also the old controls from previous benchmarks, e.g. set it to 1.12.0 to execute also the tests from cis-benchmark-1.12.0 (which is the default).

These settings can be overriden using an attributes file (e.g. --attrs <attributefile.yml>). See [sample_attributes.yml](sample_attributes.yml) as an example.

## Usage

InSpec makes it easy to run your tests wherever you need. More options listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

```sh
# run profile locally
$ git clone https://github.com/dev-sec/cis-docker-benchmark
$ inspec exec cis-docker-benchmark

# run profile locally and directly from Github
$ inspec exec https://github.com/dev-sec/cis-docker-benchmark

# run profile on remote host via SSH
inspec exec cis-docker-benchmark -t ssh://user@hostname -i /path/to/key

# run profile on remote host via SSH with sudo
inspec exec cis-docker-benchmark -t ssh://user@hostname -i /path/to/key --sudo

# run profile on remote host via SSH with sudo and define attribute value
inspec exec cis-docker-benchmark --attrs sample_attributes.yml

# run profile direct from inspec supermarket
inspec supermarket exec dev-sec/cis-docker-benchmark -t ssh://user@hostname --key-files private_key --sudo
```

### Run individual controls

In order to verify individual controls, just provide the control ids to InSpec:

```sh
inspec exec cis-docker-benchmark --controls 'cis-docker-benchmark-1.4 cis-docker-benchmark-1.5'
```

## Contributors + Kudos

* Patrick Muench [atomic111](https://github.com/atomic111)
* Dominik Richter [arlimus](https://github.com/arlimus)
* Christoph Hartmann [chris-rock](https://github.com/chris-rock)

## License and Author

* Author:: Patrick Muench <patrick.muench1111@gmail.com>
* Author:: Christoph Hartmann <chris@lollyrock.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

[1]: http://travis-ci.org/dev-sec/cis-docker-benchmark
[2]: https://gitter.im/dev-sec/general
[3]: https://downloads.cisecurity.org/
