# CIS Docker Benchmark - InSpec Profile

[![Build Status](http://img.shields.io/travis/dev-sec/cis-docker-benchmark.svg)][1]
[![Supermarket](https://img.shields.io/badge/InSpec%20Profile-CIS%20Docker%20Benchmark-brightgreen.svg)](https://supermarket.chef.io/tools/cis-docker-benchmark)
[![Gitter Chat](https://badges.gitter.im/Join%20Chat.svg)][2]

## Description

This [InSpec](https://github.com/chef/inspec) compliance profile implement the [CIS Docker 1.11.0 Benchmark](https://benchmarks.cisecurity.org/downloads/show-single/index.cfm?file=docker16.110) in an automated way to provide security best-practice tests around Docker daemon and containers in a production environment.

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Requirements

* [InSpec](https://github.com/chef/inspec)

### Platform

- Debian 8
- Ubuntu 16.04
- CentOS 7

## Attributes

We use a yml attribute file to steer the configuration, the following options are available:

  * `trusted_user: vagrant`
    define trusted user to control Docker daemon. cis-docker-benchmark-1.6

  * `authorization_plugin: authz-broker`
    define authorization plugin to manage access to Docker daemon. cis-docker-benchmark-2.11

  * `log_driver: syslog`
    define preferable way to store logs. cis-docker-benchmark-2.12

  * `log_opts: /syslog-address/`
    define Docker daemon log-opts. cis-docker-benchmark-2.12

  * `registry_cert_path: /etc/docker/certs.d`
    directory contains various Docker registry directories. cis-docker-benchmark-3.7

  * `registry_name: /etc/docker/certs.d/registry_hostname:port`
    directory contain certificate certain Docker registry. cis-docker-benchmark-3.7

  * `registry_ca_file: /etc/docker/certs.d/registry_hostname:port/ca.crt`
    certificate file for a certain Docker registry certificate files. cis-docker-benchmark-3.7 and cis-docker-benchmark-3.8

  * `container_user: vagrant`
    define user within containers. cis-docker-benchmark-4.1

  * `app_armor_profile: docker-default`
    define apparmor profile for Docker containers. cis-docker-benchmark-5.1

  * `selinux_profile: /label\:level\:s0-s0\:c1023/`
    define SELinux profile for Docker containers. cis-docker-benchmark-5.2

  * `container_capadd: null`
    define needed capabilities for containers. example: `container_capadd: NET_ADMIN,SYS_ADMIN` cis-docker-benchmark-5.3

  * `managable_container_number: 25`
    keep number of containers on a host to a manageable total. cis-docker-benchmark-6.5

## Usage

InSpec makes it easy to run your tests wherever you need. More options listed here: https://github.com/chef/inspec/blob/master/docs/ctl_inspec.rst

```
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

## Contributors + Kudos

* Patrick Muench [atomic111](https://github.com/atomic111)
* Dominik Richter [arlimus](https://github.com/arlimus)
* Christoph Hartmann [chris-rock](https://github.com/chris-rock)


## License and Author

* Author:: Patrick Muench <patrick.muench1111@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

[1]: http://travis-ci.org/dev-sec/cis-docker-benchmark
[2]: https://gitter.im/dev-sec/general
[3]: https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.11.0_Benchmark_v1.0.0.pdf
