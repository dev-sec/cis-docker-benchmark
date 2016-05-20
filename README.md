# CIS Docker InSpec Profile

supported platform ubuntu 16.04, centos7 and debian8
testes with ubuntu:latest docker image

change the username in test cis-docker-1.6
change the tls parameter (tlskey, tlscacert, tlscert) in test cis-docker-2.6
change auth plugin name in test cis-docker-2.11
change log-driver and log-opts in test cis-docker-2.12
change the test value for cis-docker-3.7
change docker_container value to your container name and change the user value in cis-docker-4.1
change docker_container and apparmor_profile in cis-docker-5.1
change docker_container and selinux label in cis-docker-5.2
change docker_container and CapAdd in cis-docker-5.3

https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.11.0_Benchmark_v1.0.0.pdf

This example shows the implementation of an InSpec [profile](../../docs/profiles.rst).
