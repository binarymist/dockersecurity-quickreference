{backmatter}

# Attributions {#attributions}

## Cover

The cover image was sourced from [Kurzon](https://upload.wikimedia.org/wikipedia/commons/8/85/Great_white_shark_size_comparison.svg) with major changes made. Licensed under [Creative Commons](https://creativecommons.org/licenses/by-sa/3.0/deed.en).

## Habitat

**Discuss many of my concerns and ideas**  
with the Docker Security team lead, Diogo Mónica  
[http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/)

**As noted by banyan**  
[https://www.banyanops.com/blog/analyzing-docker-hub/](https://www.banyanops.com/blog/analyzing-docker-hub/)  
and the morning paper  
[https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/](https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/)

**The Docker overview** says: “_Docker provides the ability to package and run an application in a loosely isolated environment_”  
[https://docs.docker.com/engine/docker-overview/](https://docs.docker.com/engine/docker-overview/)


%% Identify Risks Docker



**The Docker Registry project** is an open-source server side application that lets you store and distribute Docker images  
[https://github.com/docker/distribution](https://github.com/docker/distribution)

**Considering these processes run as root**, and have indirect access to most of the Linux Kernel  
[https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html](https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html)

**All before any security is added on top** in the form of LXC, or libcontainer (now opencontainers/runc)  
[https://github.com/opencontainers/runc](https://github.com/opencontainers/runc)

**The first place to read for solid background** on Linux kernel namespaces is the man-page  
[http://man7.org/linux/man-pages/man7/namespaces.7.html](http://man7.org/linux/man-pages/man7/namespaces.7.html)

**The hosts mounted `host-path` is shared** with all others that mount `host-path`  
[https://docs.docker.com/engine/reference/run/#volume-shared-filesystems](https://docs.docker.com/engine/reference/run/#volume-shared-filesystems) 

**If you omit the `host-path`** you can see the host path that was mounted  
[https://docs.docker.com/engine/tutorials/dockervolumes/#locating-a-volume](https://docs.docker.com/engine/tutorials/dockervolumes/#locating-a-volume) 

**Further details can be found** at the dockervolumes documentation  
[https://docs.docker.com/engine/tutorials/dockervolumes/#volume-labels](https://docs.docker.com/engine/tutorials/dockervolumes/#volume-labels)

**`PID` namespaces are hierarchically nested** in ancestor-descendant relationships to a depth of up to 32 levels  
[https://lwn.net/Articles/531419/](https://lwn.net/Articles/531419/) 

**The default behaviour can however be overridden** to allow a container to be able to access processes within a sibling container, or the hosts `PID` namespace  
[https://docs.docker.com/engine/reference/run/#pid-settings---pid](https://docs.docker.com/engine/reference/run/#pid-settings---pid)

**As an aside, `PID` namespaces give us the functionality** of "_suspending/resuming the set of processes in the container and migrating the container to a new host while the processes inside the container maintain the same PIDs._"  
[http://man7.org/linux/man-pages/man7/pid_namespaces.7.html](http://man7.org/linux/man-pages/man7/pid_namespaces.7.html)  
with a handful of commands  
https://www.fir3net.com/Containers/Docker/the-essential-guide-in-transporting-your-docke  
r-containers.html

**A UTS namespace** is the set of identifiers returned by `uname`  
[http://man7.org/linux/man-pages/man2/clone.2.html](http://man7.org/linux/man-pages/man2/clone.2.html)

**When a container is created**, a UTS namespace is copied (`CLONE_NEWUTS` is set)  
https://github.com/docker/libcontainer/blob/83a102cc68a09d890cce3b6c2e5c14c49e6373a0/S  
PEC.md

**When a container is created** with `--uts="host"` a UTS namespace is inherited from the host  
[https://docs.docker.com/engine/reference/run/#uts-settings---uts](https://docs.docker.com/engine/reference/run/#uts-settings---uts)

**According to the namespaces man page** "_Objects created in an IPC namespace are visible to all other processes that are members of that namespace, but are not visible to processes in other IPC namespaces._"  
[http://man7.org/linux/man-pages/man7/namespaces.7.html](http://man7.org/linux/man-pages/man7/namespaces.7.html)

**This behaviour can be overridden** to allow a (any) container to reuse another containers or the hosts message queues, semaphores, and shared memory via their IPC namespace  
[https://docs.docker.com/engine/reference/run/#ipc-settings---ipc](https://docs.docker.com/engine/reference/run/#ipc-settings---ipc)

**You can see using the command** supplied from the CIS_Docker_1.13.0_Benchmark  
[https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf)

**There are currently some Docker features** that are incompatible with using user namespaces  
[https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-user-namespace-options](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-user-namespace-options) 

**Docker engine reference** provides additional details around known restrictions of user namespaces  
[https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-user-namespace-options](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-user-namespace-options)

**Cgroups have been available** in the Linux kernel since January 2008 (2.6.24)  
[https://kernelnewbies.org/Linux_2_6_24#head-5b7511c1e918963d347abc8ed4b75215877d3aa3](https://kernelnewbies.org/Linux_2_6_24#head-5b7511c1e918963d347abc8ed4b75215877d3aa3)

**According to the Linux man page for capabilities** "_Linux divides the privileges traditionally associated with superuser into distinct units, known as capabilities, which can be independently enabled and disabled_"  
[http://man7.org/linux/man-pages/man7/capabilities.7.html](http://man7.org/linux/man-pages/man7/capabilities.7.html)

**Dan Walsh** who is one of the experts when it comes to applying least privilege to containers, also discusses these  
[http://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/](http://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/)

**Open Container Initiative (OCI) runC specification**  
https://github.com/opencontainers/runc/tree/6c22e77604689db8725fa866f0f2ec0b3e8c3a07#r  
unning-containers

**As stated on the Docker Engine security page** "_One primary risk with running Docker containers is that the default set of capabilities and mounts given to a container may provide incomplete isolation, either independently, or when used in combination with kernel vulnerabilities._"  
[https://docs.docker.com/engine/security/security/](https://docs.docker.com/engine/security/security/)

**The core Unix security model** which is a form of Discretionary Access Control (DAC) was inherited by Linux  
[https://en.wikipedia.org/wiki/Discretionary_access_control](https://en.wikipedia.org/wiki/Discretionary_access_control)

**The Unix DAC was designed in 1969**  
[https://www.linux.com/learn/overview-linux-kernel-security-features](https://www.linux.com/learn/overview-linux-kernel-security-features)

**The first version of SecComp** was merged into the Linux kernel mainline in version 2.6.12 (March 8 2005)  
https://git.kernel.org/cgit/linux/kernel/git/tglx/history.git/commit/?id=d949d0ec9c601f2b148be  
d3cdb5f87c052968554

**In order to enable SecComp for a given process**, you would write a `1` to `/proc/<PID>/seccomp`  
[https://lwn.net/Articles/656307/](https://lwn.net/Articles/656307/)

**Then the addition of the `seccomp()`** System call in 2014 to the kernel version 3.17 along with popular applications such as Chrome/Chromium, OpenSSH  
[https://en.wikipedia.org/wiki/Seccomp](https://en.wikipedia.org/wiki/Seccomp)

**Docker has disabled about 44 system calls** in its default (seccomp) container profile  
[https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)  
[https://github.com/docker/docker/blob/master/profiles/seccomp/default.json](https://github.com/docker/docker/blob/master/profiles/seccomp/default.json)

**The `keyctl` System call** was removed from the default Docker container profile after vulnerability CVE-2016-0728 was discovered, which allows privilege escalation or denial of service  
[https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2016-0728](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2016-0728)  
[https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2014-3153](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2014-3153)


%% End Identify Risks Docker






%% Countermeasures Docker

**Cisecurity has an excellent resource** for hardening docker images which the Docker Security team helped with  
[https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf)

**"_Docker Security Scanning_** _is available as an add-on to Docker hosted private repositories on both Docker Cloud and Docker Hub._", you also have to opt in and pay for it  
https://docs.docker.com/docker-cloud/builds/image-scan  
/#opt-in-to-docker-security-scanning

**Docker Security Scanning** is also now available on the new Enterprise Edition  
[https://blog.docker.com/2017/03/docker-enterprise-edition/](https://blog.docker.com/2017/03/docker-enterprise-edition/)

**Whether un-official or official**  
[https://github.com/docker-library/official-images](https://github.com/docker-library/official-images)

**Docker Content Trust**  
[https://blog.docker.com/2015/08/content-trust-docker-1-8/](https://blog.docker.com/2015/08/content-trust-docker-1-8/)

**Notary**  
[https://github.com/docker/notary](https://github.com/docker/notary)

**`DOCKER_CONTENT_TRUST`** environment variable must be set to `1`  
https://docs.docker.com/engine/security/trust/content_trust/#enable-and-disable-content-tr  
ust-per-shell-or-per-invocation

**`DOCKER_CONTENT_TRUST_SERVER`** must be set to the URL of the Notary server you setup  
[https://docs.docker.com/engine/reference/commandline/cli/#environment-variables](https://docs.docker.com/engine/reference/commandline/cli/#environment-variables)

**They need to generate a key pair**  
[https://docs.docker.com/engine/security/trust/trust_delegation/](https://docs.docker.com/engine/security/trust/trust_delegation/)

**Notary is based on a Go implementation** of The Update Framework (TUF)  
[https://theupdateframework.github.io/](https://theupdateframework.github.io/)

**An example of the NodeGoat image**  
[https://github.com/owasp/nodegoat](https://github.com/owasp/nodegoat)

**The space for tooling** to help find vulnerabilities in code, packages, etc within your Docker images has been noted, and tools provided  
https://community.alfresco.com/community/ecm/blog/2015/12/03/docker-security-tools-aud  
it-and-vulnerability-assessment/

**These tools should form** a part of your secure and trusted build pipeline / software supply-chain  
[https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/](https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/)

**Dockerfile linter** that helps you build best practice Docker images  
[https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/](https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/)

**Free and open source auditing tool** for Linux/Unix based systems  
[https://github.com/CISOfy/lynis](https://github.com/CISOfy/lynis)

**Docker plugin available** which allows one to audit Docker  
[https://cisofy.com/lynis/plugins/docker-containers/](https://cisofy.com/lynis/plugins/docker-containers/) 

**Hashes of the CVE data sources**  
[https://github.com/coreos/clair/tree/f66103c7732c9a62ba1d3afc26437ae54953dc01#default-data-sources](https://github.com/coreos/clair/tree/f66103c7732c9a62ba1d3afc26437ae54953dc01#default-data-sources)

**Collector has a pluggable, extensible architecture**  
[https://github.com/banyanops/collector/blob/master/docs/CollectorDetails.md](https://github.com/banyanops/collector/blob/master/docs/CollectorDetails.md)

**Banyanops was the organisation** that blogged about the high number of vulnerable packages on Docker Hub  
[https://www.banyanops.com/blog/analyzing-docker-hub/](https://www.banyanops.com/blog/analyzing-docker-hub/)

**Seen by running `docker network ls`**  
[https://docs.docker.com/engine/reference/commandline/network_ls/](https://docs.docker.com/engine/reference/commandline/network_ls/)

**Docker network**  
[https://docs.docker.com/engine/userguide/networking/](https://docs.docker.com/engine/userguide/networking/)

**Network drivers** created by docker  
[https://docs.docker.com/engine/reference/run/#network-settings](https://docs.docker.com/engine/reference/run/#network-settings)

**`bridge`**  
[https://docs.docker.com/engine/reference/run/#network-bridge](https://docs.docker.com/engine/reference/run/#network-bridge)

**`none`**  
[https://docs.docker.com/engine/reference/run/#network-none](https://docs.docker.com/engine/reference/run/#network-none)

**`host`**  
[https://docs.docker.com/engine/reference/run/#network-host](https://docs.docker.com/engine/reference/run/#network-host)

**`container`**  
[https://docs.docker.com/engine/reference/run/#network-container](https://docs.docker.com/engine/reference/run/#network-container)

**`nsenter`** command  
[http://man7.org/linux/man-pages/man1/nsenter.1.html](http://man7.org/linux/man-pages/man1/nsenter.1.html)

**Understand container communication**  
[https://docs.docker.com/engine/userguide/networking/default_network/container-communication/](https://docs.docker.com/engine/userguide/networking/default_network/container-communication/)

**The username must exist** in the `/etc/passwd` file, the `sbin/nologin` users are valid also  
[https://success.docker.com/KBase/Introduction_to_User_Namespaces_in_Docker_Engine](https://success.docker.com/KBase/Introduction_to_User_Namespaces_in_Docker_Engine)

**"_The UID/GID we want to remap to_** _does not need to match the UID/GID of the username in `/etc/passwd`_"  
[https://success.docker.com/KBase/Introduction_to_User_Namespaces_in_Docker_Engine](https://success.docker.com/KBase/Introduction_to_User_Namespaces_in_Docker_Engine)

**Files will be populated** with a contiguous 65536 length range of subordinate user and group Ids respectively  
[https://docs.docker.com/engine/security/userns-remap/](https://docs.docker.com/engine/security/userns-remap/)

**Check out the Docker engine reference**  
Updated URL: https://github.com/jquast/docker/blob/2fd674a00f98469caa1ceb572e5ae92a68b52f44/docs/reference/commandline/dockerd.md#detailed-information-on-subuidsubgid-ranges

**Check the Runtime constraints on resources**  
[https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)

**Limit a container's resources** Admin Guide for Docker Engine  
[https://docs.docker.com/engine/admin/resource_constraints/](https://docs.docker.com/engine/admin/resource_constraints/)

**By default Docker** uses the cgroupfs cgroup driver to interface with the Linux kernel's cgroups  
[https://docs.docker.com/engine/reference/commandline/dockerd/#options-for-the-runtime](https://docs.docker.com/engine/reference/commandline/dockerd/#options-for-the-runtime)

**`docker stats`** command, which will give you a line with your containers CPU usage, Memory usage and Limit, Net I/O, Block I/O, Number of PIDs  
[https://docs.docker.com/engine/reference/commandline/stats/](https://docs.docker.com/engine/reference/commandline/stats/)

**Docker engine runtime metrics**  
[https://docs.docker.com/engine/admin/runmetrics/](https://docs.docker.com/engine/admin/runmetrics/)

**With a little help from the CIS Docker Benchmark** we can use the `PID`s cgroup limit  
[https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf)

**There are several ways you can minimise your set of capabilities**  
[http://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/](http://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/)

**First Linux kernel summit**  
[https://lwn.net/2001/features/KernelSummit/](https://lwn.net/2001/features/KernelSummit/)

**It was decided to** have the developers interested in security create a "_generic interface which could be used by any security policy. The result was the Linux Security Modules (LSM)_" API/framework, which provides many hooks at security critical points within the kernel  
[http://www.hep.by/gnu/kernel/lsm/](http://www.hep.by/gnu/kernel/lsm/)  
[https://lwn.net/Articles/180194/](https://lwn.net/Articles/180194/)  
[https://www.linux.com/learn/overview-linux-kernel-security-features](https://www.linux.com/learn/overview-linux-kernel-security-features) 

**Selectable at build-time** via `CONFIG_DEFAULT_SECURITY`  
[https://www.kernel.org/doc/Documentation/security/LSM.txt](https://www.kernel.org/doc/Documentation/security/LSM.txt)

**Overridden at boot-time** via the `security=...` kernel command line argument  
[https://debian-handbook.info/browse/stable/sect.selinux.html#sect.selinux-setup](https://debian-handbook.info/browse/stable/sect.selinux.html#sect.selinux-setup)

**"_Most LSMs choose to extend the capabilities_** _system, building their checks on top of the defined capability hooks._"  
[https://www.kernel.org/doc/Documentation/security/LSM.txt](https://www.kernel.org/doc/Documentation/security/LSM.txt) 

**AppArmor policy's are created using the profile language**  
[http://wiki.apparmor.net/index.php/ProfileLanguage](http://wiki.apparmor.net/index.php/ProfileLanguage)

**Apparmor page** of Dockers Secure Engine  
[https://docs.docker.com/engine/security/apparmor/](https://docs.docker.com/engine/security/apparmor/)

**SELinux needs to be installed and configured on Debian**  
[https://wiki.debian.org/SELinux/Setup](https://wiki.debian.org/SELinux/Setup)

**SELinux support for the Docker daemon is disabled by default** and needs to be enabled  
[https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines](https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines)  
[https://docs.docker.com/engine/reference/commandline/dockerd/](https://docs.docker.com/engine/reference/commandline/dockerd/)

**Docker daemon options** can also be set within the daemon configuration file  
[https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-file)

**Label confinement for the container** can be configured using `--security-opt`  
[https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines](https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines)

**SELinux Labels for Docker** consist of four parts  
[https://www.projectatomic.io/docs/docker-and-selinux/](https://www.projectatomic.io/docs/docker-and-selinux/)

**SELinux can be enabled in the container** using `setenforce 1`  
[http://www.unix.com/man-page/debian/8/setenforce/](http://www.unix.com/man-page/debian/8/setenforce/)

**SELinux can operate in one of three modes**  
[https://www.centos.org/docs/5/html/5.2/Deployment_Guide/sec-sel-enable-disable-enforcement.html](https://www.centos.org/docs/5/html/5.2/Deployment_Guide/sec-sel-enable-disable-enforcement.html)

**To persist on boot: In Debian**  
[https://debian-handbook.info/browse/stable/sect.selinux.html#sect.selinux-setup](https://debian-handbook.info/browse/stable/sect.selinux.html#sect.selinux-setup)

**Kernel is configured with** `CONFIG_SECCOMP`  
[https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)

**Default seccomp profile for containers** (`default.json`)  
[https://github.com/docker/docker/blob/master/profiles/seccomp/default.json](https://github.com/docker/docker/blob/master/profiles/seccomp/default.json)

**Apply the `--tmpfs` flag**  
[https://docs.docker.com/engine/reference/commandline/run/#mount-tmpfs---tmpfs](https://docs.docker.com/engine/reference/commandline/run/#mount-tmpfs---tmpfs)

**libcontainer**  
[https://github.com/opencontainers/runc/tree/master/libcontainer](https://github.com/opencontainers/runc/tree/master/libcontainer)

**containerd** (daemon for Linux or Windows) is based on the Docker engine's core container runtime  
[https://containerd.io/](https://containerd.io/) 

**runC** is the container runtime that runs containers  
[https://runc.io/](https://runc.io/)

**runC** was created by the OCI  
[https://github.com/opencontainers/runc](https://github.com/opencontainers/runc)

**runC can be installed separately**  
https://docker-saigon.github.io/post/Docker-Internals/#runc:cb6baf67dddd3a71c07abfd705d  
c7d4b

**Host independent** `config.json` and host specific `runtime.json` files  
[https://github.com/containerd/containerd/blob/0.0.5/docs/bundle.md#configs](https://github.com/containerd/containerd/blob/0.0.5/docs/bundle.md#configs)

**You must also construct or export a root filesystem**  
[https://github.com/opencontainers/runc#creating-an-oci-bundle](https://github.com/opencontainers/runc#creating-an-oci-bundle)

**The most common attack vectors** are still attacks focussing on our weakest areas, such as people, password stealing, spear phishing, uploading and execution of web shells, compromising social media accounts, weaponised documents, and ultimately application security, as I have mentioned many times before  
[https://blog.binarymist.net/presentations-publications/#nzjs-2017-the-art-of-exploitation](https://blog.binarymist.net/presentations-publications/#nzjs-2017-the-art-of-exploitation)

**It is pretty clear** that there are far more vulnerabilities affecting VMs than there are affecting containers  
[https://xenbits.xen.org/xsa/](https://xenbits.xen.org/xsa/)  
[https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=docker](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=docker)

**Bugs listed in the Xen CVEs**  
[https://xenbits.xen.org/xsa/](https://xenbits.xen.org/xsa/)

**Show #7 Understanding Container Security**  
http://www.heavybit.com/library/podcasts/the-secure-developer/ep-7-understanding-contai  
ner-security/

%% End Countermeasures Docker
