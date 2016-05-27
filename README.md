# CIS Docker Benchmark - InSpec Profile

## Description

This [InSpec](https://github.com/chef/inspec) compliance profile implement the [CIS Docker 1.11.0 Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.11.0_Benchmark_v1.0.0.pdf) in an automated way to provide security best-practices tests around Docker daemon and containers in a production environment.

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Requirements

* [InSpec](https://github.com/chef/inspec)

### Platform

- Debian 8
- Ubuntu 16.04
- CentOS 7

## Usage

InSpec makes it easy to run your tests wherever you need. More options listed here: https://github.com/chef/inspec/blob/master/docs/ctl_inspec.rst

```
# run profile locally
$ git clone https://github.com/dev-sec/cis-docker
$ inspec exec cis-docker

# run profile locally and directly from Github
$ inspec exec https://github.com/dev-sec/cis-docker

# run profile on remote host via SSH
inspec exec cis-docker -t ssh://user@hostname -i /path/to/key

# run profile on remote host via SSH with sudo
inspec exec cis-docker -t ssh://user@hostname -i /path/to/key --sudo
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

change the username in test cis-docker-1.6
change the tls parameter (tlskey, tlscacert, tlscert) in test cis-docker-2.6
change auth plugin name in test cis-docker-2.11
change log-driver and log-opts in test cis-docker-2.12
change the test value for cis-docker-3.7
change docker_container value to your container name and change the user value in cis-docker-4.1
change docker_container and apparmor_profile in cis-docker-5.1
change docker_container and selinux label in cis-docker-5.2
change docker_container and CapAdd in cis-docker-5.3

[1]: https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.11.0_Benchmark_v1.0.0.pdf
