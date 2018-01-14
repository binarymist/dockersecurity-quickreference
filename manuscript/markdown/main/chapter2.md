# 2. Hardening Docker Host, Engine and Containers {#hardening-docker-host-engine-and-containers}

![](images/ThreatTags/difficult-uncommon-average-moderate.png)

Considering that these processes run as root, and have [indirect access](https://theinvisiblethings.blogspot.co.nz/2012/09/how-is-qubes-os-different-from.html) to most of the Linux Kernel (20+ million lines of code written by humans) APIs, such as networking, USB, storage stacks, and others via System calls, the situation may look bleak.

![](images/HypervisorVsContainers.png)

[System calls](http://man7.org/linux/man-pages/man2/syscalls.2.html) are how programmes access the kernel to perform tasks. This attack surface is huge, and all before any security is added on top in the form of LXC, libcontainer (now [opencontainers/runc](https://github.com/opencontainers/runc)), or [Linux Security Modules (LSM)](#docker-host-engine-and-containers-linux-security-modules) such as AppArmor or SELinux. These are often seen as an annoyance and just disabled like many other forms of security.

If you run a container, you may have to install `kmod`, then run `lsmod` in the container, and also on the host system. You will see that the same modules are loaded, this is because as mentioned, the container shares the host kernel, so there is not a lot between processes within the container and the host kernel. As mentioned above, the processes within the container may be running as root as well, it pays for you to have a good understanding of the security features Docker provides, and how to employ them.

The [Seccomp section below](#docker-engine-and-containers-seccomp) discusses Docker's attempt to put a stop to some System calls accessing the kernel APIs. There are also many other features that Docker has added or leveraged in terms of mitigating a lot of this potential abuse. Although the situation initially looks bad, Docker has done a lot to improve it.

As you can see in the above image, the host kernel is open to receiving potential abuse from containers. Make sure you keep it patched. We will now walk though many areas of potential abuse.

{#vps-countermeasures-docker-hardening-docker-host-engine-and-containers}
![](images/ThreatTags/PreventionDIFFICULT.png)

Make sure you keep your host kernel well patched, as it is a huge attack surface, with all of your containers accessing it via System calls.

The space for tooling to help find vulnerabilities in code, packages, etc within your Docker images has been noted, and [tools provided](https://community.alfresco.com/community/ecm/blog/2015/12/03/docker-security-tools-audit-and-vulnerability-assessment/). The following is a sorted list of what feels like does the least and is the simplest in terms of security/hardening features to what does the most, not understating tools that do a little, but do it well.

These tools should form a part of your secure and trusted build pipeline, or [software supply-chain](https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/).

## [Haskell Dockerfile Linter](https://github.com/lukasmartinelli/hadolint)

"_A smarter Dockerfile linter that helps you build_ [_best practice Docker images_](https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/)."

## [Lynis](https://cisofy.com/downloads/)

Lynis is a mature, free and [open source](https://github.com/CISOfy/lynis) auditing tool for Linux/Unix based systems. There is a [Docker plugin](https://cisofy.com/lynis/plugins/docker-containers/) available which allows one to audit Docker, its configuration and containers, but an enterprise license is required, although it is inexpensive.
