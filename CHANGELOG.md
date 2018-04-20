# Change Log

## [2.1.0](https://github.com/dev-sec/cis-docker-benchmark/tree/2.1.0) (2018-04-20)
[Full Changelog](https://github.com/dev-sec/cis-docker-benchmark/compare/2.0.0...2.1.0)

**Closed issues:**

- method\_missing: undefined local variable or method docker [\#50](https://github.com/dev-sec/cis-docker-benchmark/issues/50)
- uploading cis docker profile to chef compliance [\#46](https://github.com/dev-sec/cis-docker-benchmark/issues/46)

**Merged pull requests:**

- Fix utf8 truncated output [\#53](https://github.com/dev-sec/cis-docker-benchmark/pull/53) ([aschmidt75](https://github.com/aschmidt75))
- update inspec version to 2.0 [\#52](https://github.com/dev-sec/cis-docker-benchmark/pull/52) ([atomic111](https://github.com/atomic111))
- Fixes \#37 prevent NoMethodError when no hosts available [\#49](https://github.com/dev-sec/cis-docker-benchmark/pull/49) ([Nowheresly](https://github.com/Nowheresly))
- name correct minimum inspec version [\#47](https://github.com/dev-sec/cis-docker-benchmark/pull/47) ([chris-rock](https://github.com/chris-rock))
- update changelog [\#45](https://github.com/dev-sec/cis-docker-benchmark/pull/45) ([chris-rock](https://github.com/chris-rock))

## [2.0.0](https://github.com/dev-sec/cis-docker-benchmark/tree/2.0.0) (2017-11-24)
[Full Changelog](https://github.com/dev-sec/cis-docker-benchmark/compare/1.3.1...2.0.0)

**Closed issues:**

- Verify enable content trust per-shell or per-invocation check [\#44](https://github.com/dev-sec/cis-docker-benchmark/issues/44)
- load\_with\_context': undefined method `each' for nil:NilClass \(NoMethodError\) exception in cis-docker-benchmark-master/controls/container\_runtime.rb:194 [\#37](https://github.com/dev-sec/cis-docker-benchmark/issues/37)
- use own control number scheme [\#25](https://github.com/dev-sec/cis-docker-benchmark/issues/25)
- Update to CIS 1.13 [\#24](https://github.com/dev-sec/cis-docker-benchmark/issues/24)

**Merged pull requests:**

- Update to CIS Docker Benchmark 1.13.0 [\#43](https://github.com/dev-sec/cis-docker-benchmark/pull/43) ([atomic111](https://github.com/atomic111))
- correct the maintainer and email in inspec.yml [\#42](https://github.com/dev-sec/cis-docker-benchmark/pull/42) ([atomic111](https://github.com/atomic111))
- update gemfile [\#41](https://github.com/dev-sec/cis-docker-benchmark/pull/41) ([atomic111](https://github.com/atomic111))

## [1.3.1](https://github.com/dev-sec/cis-docker-benchmark/tree/1.3.1) (2017-11-18)
[Full Changelog](https://github.com/dev-sec/cis-docker-benchmark/compare/1.3.0...1.3.1)

**Fixed bugs:**

- undefined method `downcase' for nil:NilClass [\#32](https://github.com/dev-sec/cis-docker-benchmark/issues/32)

**Closed issues:**

- docker variable not defined [\#31](https://github.com/dev-sec/cis-docker-benchmark/issues/31)

**Merged pull requests:**

- 1.3.1 [\#40](https://github.com/dev-sec/cis-docker-benchmark/pull/40) ([chris-rock](https://github.com/chris-rock))
- updating check for container\_info networkings port [\#38](https://github.com/dev-sec/cis-docker-benchmark/pull/38) ([coolguru](https://github.com/coolguru))
- add required docker cli version [\#35](https://github.com/dev-sec/cis-docker-benchmark/pull/35) ([chris-rock](https://github.com/chris-rock))
- use recommended spdx license identifier [\#34](https://github.com/dev-sec/cis-docker-benchmark/pull/34) ([chris-rock](https://github.com/chris-rock))
- Due to inspec deprecation warnings [\#33](https://github.com/dev-sec/cis-docker-benchmark/pull/33) ([alexpop](https://github.com/alexpop))

## [1.3.0](https://github.com/dev-sec/cis-docker-benchmark/tree/1.3.0) (2017-04-28)
[Full Changelog](https://github.com/dev-sec/cis-docker-benchmark/compare/1.2.0...1.3.0)

**Closed issues:**

- rename control titles [\#22](https://github.com/dev-sec/cis-docker-benchmark/issues/22)
- splitt controls in components [\#21](https://github.com/dev-sec/cis-docker-benchmark/issues/21)
- include the inspec docker resource [\#20](https://github.com/dev-sec/cis-docker-benchmark/issues/20)
- Update to CIS Docker 1.12.0 Benchmark [\#11](https://github.com/dev-sec/cis-docker-benchmark/issues/11)
- tag the tests which belongs to a host and to a container [\#8](https://github.com/dev-sec/cis-docker-benchmark/issues/8)

**Merged pull requests:**

- fix \#11 implement missing 1.12 controls [\#30](https://github.com/dev-sec/cis-docker-benchmark/pull/30) ([chris-rock](https://github.com/chris-rock))
- use new inspec docker resource [\#29](https://github.com/dev-sec/cis-docker-benchmark/pull/29) ([chris-rock](https://github.com/chris-rock))
- split up control files into components [\#26](https://github.com/dev-sec/cis-docker-benchmark/pull/26) ([chris-rock](https://github.com/chris-rock))
- update tags and refs [\#23](https://github.com/dev-sec/cis-docker-benchmark/pull/23) ([chris-rock](https://github.com/chris-rock))

## [1.2.0](https://github.com/dev-sec/cis-docker-benchmark/tree/1.2.0) (2017-04-18)
[Full Changelog](https://github.com/dev-sec/cis-docker-benchmark/compare/1.1.1...1.2.0)

**Merged pull requests:**

- update to CIS Benchmark 1.12, controls 1.1 to 2.16 [\#19](https://github.com/dev-sec/cis-docker-benchmark/pull/19) ([atomic111](https://github.com/atomic111))

## [1.1.1](https://github.com/dev-sec/cis-docker-benchmark/tree/1.1.1) (2017-03-01)
[Full Changelog](https://github.com/dev-sec/cis-docker-benchmark/compare/1.1.0...1.1.1)

**Merged pull requests:**

- Fix 'or' in controls 5.1 and 5.2 [\#18](https://github.com/dev-sec/cis-docker-benchmark/pull/18) ([emilyh315](https://github.com/emilyh315))
- add changelog [\#16](https://github.com/dev-sec/cis-docker-benchmark/pull/16) ([chris-rock](https://github.com/chris-rock))

## [1.1.0](https://github.com/dev-sec/cis-docker-benchmark/tree/1.1.0) (2016-12-13)
[Full Changelog](https://github.com/dev-sec/cis-docker-benchmark/compare/1.0.0...1.1.0)

**Merged pull requests:**

- update Gemfile and fix rubocop issues [\#15](https://github.com/dev-sec/cis-docker-benchmark/pull/15) ([atomic111](https://github.com/atomic111))
- Edit control "cis-docker-benchmark-3.4" [\#14](https://github.com/dev-sec/cis-docker-benchmark/pull/14) ([emilyh315](https://github.com/emilyh315))
- Edit control "cis-docker-benchmark-1.11" [\#13](https://github.com/dev-sec/cis-docker-benchmark/pull/13) ([emilyh315](https://github.com/emilyh315))
- Fix README.md [\#12](https://github.com/dev-sec/cis-docker-benchmark/pull/12) ([netflash](https://github.com/netflash))

## [1.0.0](https://github.com/dev-sec/cis-docker-benchmark/tree/1.0.0) (2016-07-05)
**Implemented enhancements:**

- use new InSpec attributes [\#10](https://github.com/dev-sec/cis-docker-benchmark/pull/10) ([chris-rock](https://github.com/chris-rock))
- handle nil results for docker.path [\#6](https://github.com/dev-sec/cis-docker-benchmark/pull/6) ([chris-rock](https://github.com/chris-rock))
- externalize reoccurring calls to docker resource [\#4](https://github.com/dev-sec/cis-docker-benchmark/pull/4) ([chris-rock](https://github.com/chris-rock))
- determine attribute values at the beginning [\#1](https://github.com/dev-sec/cis-docker-benchmark/pull/1) ([chris-rock](https://github.com/chris-rock))

**Merged pull requests:**

- fix ips for vagrant machines [\#9](https://github.com/dev-sec/cis-docker-benchmark/pull/9) ([chris-rock](https://github.com/chris-rock))
- change order of InSpec img shield in README.md [\#7](https://github.com/dev-sec/cis-docker-benchmark/pull/7) ([atomic111](https://github.com/atomic111))
- add ruby 2.3.1 to travis.yml [\#5](https://github.com/dev-sec/cis-docker-benchmark/pull/5) ([atomic111](https://github.com/atomic111))
- changed link to CIS Docker Benchmark document [\#3](https://github.com/dev-sec/cis-docker-benchmark/pull/3) ([atomic111](https://github.com/atomic111))
- add Vagrantfile to repo [\#2](https://github.com/dev-sec/cis-docker-benchmark/pull/2) ([atomic111](https://github.com/atomic111))



\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*