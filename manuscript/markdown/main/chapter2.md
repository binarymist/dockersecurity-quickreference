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

## [Docker Bench](https://github.com/docker/docker-bench-security)

Docker Bench is a shell script that can be downloaded from GitHub and executed immediately, run from a pre-built container, or using Docker Compose after Git cloning. Docker Bench tests many host configurations and Docker containers against the CIS Docker Benchmark.

## CoreOS [Clair](https://github.com/coreos/clair)

CoreOS is an open source project that appears to do a similar job to Docker Security Scanning, but it is free. You can use it on any image you pull, to compare the hashes of the packages from every container layer within, with hashes of the [CVE data sources](https://github.com/coreos/clair/tree/f66103c7732c9a62ba1d3afc26437ae54953dc01#default-data-sources). You could also use Clair on your CI/CD build to stop images being deployed if they have packages with hashes that match those of the CVE data sources. quay.io was the first container registry to integrate with Clair.

## Banyanops [collector](https://github.com/banyanops/collector)

Banyanops is a free and open source framework for static analysis of Docker images. It does more than Clair, it can optionally communicate with Docker registries, private or Docker Hub, to obtain image hashes, and it can then tell Docker Daemon to pull the images locally. Collector then `docker run`'s each container in turn to be inspected. Each container runs a banyan or user-specified script which outputs the results to stdout. Collector collates the containers output, and can send this to Banyan Analyser for further analysis. Collector has a [pluggable, extensible architecture](https://github.com/banyanops/collector/blob/master/docs/CollectorDetails.md). Collector can also: enforce policies, such as no unauthorised user accounts, etc. Make sure components are in their correct location. Banyanops was the organisation that [blogged](https://www.banyanops.com/blog/analyzing-docker-hub/) about the high number of vulnerable packages on Docker Hub. They have really put their money where their mouth was now.

## [Anchore](https://anchore.com/solutions/)

Anchore is a set of tools that provide visibility, control, analytics, compliance and governance for containers in the cloud or on-prem for a fee.  
There are two main parts, a hosted web service, and a set of open source CLI query tools.  
The hosted service selects and analyses popular container images from Docker Hub and other registries. The metadata it creates is provided as a service to the on-premise CLI tools.  
It performs a similar job to that of Clair, but does not look as simple. It also looks for source code secrets, API keys, passwords, etc. in images.

It's designed to integrate into your CI/CD pipeline and integrates with Kubernetes, Docker, Jenkins, CoreOS, Mesos

## [TwistLock](https://www.twistlock.com/) {#vps-countermeasures-docker-hardening-docker-host-engine-and-containers-twistlock}

TwistLock is a fairly comprehensive and complete proprietary offering with a free developer edition. The following details were taken from TwistLock marketing pages:

Features of Trust:

* Discover and manage vulnerabilities in images
* Uses CVE data sources similar to CoreOS Clair
* Can scan registries: Docker Hub, Google Container Registry, EC2 Container Registry, Artifactory, Nexus Registry, and images for vulnerabilities in code and configuration
* Enforce and verify standard configurations
* Hardening checks on images based on CIS Docker benchmark
* Real-time vulnerability and threat intelligence
* Provide out-of-box plugins for vulnerability reporting directly into Jenkins and TeamCity
* Provides a set of APIs for developers to access almost all of the TwistLock core functions

Features of Runtime:

* Policy enforcement
* Detect anomalies, uses open source CVE feeds, commercial threat and vulnerability sources, as well as TwistLock's own Lab research
* Defend and adapt against active threats and compromises using machine learning
* Governs access control to individual APIs of Docker Engine, Kubernetes, and Docker Swarm, providing LDAP/AD integration.

## Possible contenders to watch

* [Drydock](https://github.com/zuBux/drydock) is a similar offering to Docker Bench, but not as mature at this stage
* [Actuary](https://github.com/diogomonica/actuary) is a similar offering to Docker Bench, but not as mature at this stage. I [discussed](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) this project briefly with its creator Diogo Mónica, and it sounds like the focus is on creating a better way of running privileged services on swarm, instead of investing time into this.

## Namespaces {#vps-identify-risks-docker-docker-host-engine-and-containers-namespaces}

The first place to read for solid background on Linux kernel namespaces is the [man-page](http://man7.org/linux/man-pages/man7/namespaces.7.html), otherwise I'd just be repeating what is there. A lot of what follows about namespaces requires some knowledge from the namespaces man-page, so do yourself a favour and read it first.

Linux kernel namespaces were first added between 2.6.15 (January 2006) and 2.6.26 (July 2008).

According to the namespaces man page, IPC, network and UTS namespace support was available from kernel version 3.0, while mount, PID and user namespace support was available from kernel version 3.8 (February 2013), and cgroup namespace support was available from kernel version 4.6 (May 2016).

Each aspect of a container runs in a separate namespace and its access is limited to that namespace.

Docker leverages the Linux (kernel) namespaces which provide an isolated workspace wrapped with a global system resource abstraction. This makes it appear to the processes within the namespace that they have their own isolated instance of the global resource. When a container is run, Docker creates a set of namespaces for that container, providing a layer of isolation between containers:

1. `mnt`: (Mount) Provides filesystem isolation by managing filesystems and mount points. The `mnt` namespace allows a container to have its own isolated set of mounted filesystems, the propagation modes can be one of the following: [`r`]`shared`, [`r`]`slave` or [`r`]`private`. The `r` means recursive.
    
    If you run the following command, then the host's mounted `host-path` is [shared](https://docs.docker.com/engine/admin/volumes/volumes/#create-and-manage-volumes) with all others that mount `host-path`. Any changes made to the mounted data will be propagated to those that use the `shared` mode propagation. Using `slave` means only the master (`host-path`) is able to propagate changes, not vice-versa. Using `private` which is the default, will ensure no changes can be propagated.
    
    {title="Mounting volumes in shared mode propagation", linenos=off, lang=bash}
        docker run <run arguments> --volume=[host-path:]<container-path>:[z][r]shared <container image name or id> <command> <args...>
    
    If you omit the `host-path` you can [see the host path](https://docs.docker.com/engine/tutorials/dockervolumes/#locating-a-volume) that was mounted when running the following command:
    
    {title="Query", linenos=off, lang=bash}
        docker inspect <name or id of container>
    
    Find the "Mounts" property in the JSON produced. It will have a "Source" and "Destination" similar to:
    
    {title="Result", linenos=off, lang=json}
        ...
        "Mounts": [
          {
            "Name": "<container id>",
            "Source": "/var/lib/docker/volumes/<container id>/_data",
            "Destination": "<container-path>",
            "Mode": "",
            "RW": true,
            "Propagation": "shared"
          }
        ]
        ...
    
    An empty string for Mode means that it is set to its read-write default. For example, a container can mount sensitive host system directories such as `/`, `/boot`, `/etc`, `/lib`, `/proc`, `/sys`, along with the rest as I discuss in the Lock Down the Mounting of Partitions section of my book [Fascicle 1 of Holistic Info-Sec for Web Developers](https://f1.holisticinfosecforwebdevelopers.com/), particularly if that advice is not followed. If it is followed, you have some defence in depth working for you, and although Docker may have mounted a directory as read-write, the underlying mount may be read-only, thus stopping the container from being able to modify files in these locations on the host system. If the host does not have the above directories mounted with constrained permissions, then we are relying on the user running any given Docker container that mounts a sensitive host volume to mount it as read-only. For example, after the following command has been run, users within the container can modify files in the hosts `/etc` directory:
    
    {title="Vulnerable mount", linenos=off, lang=bash}
        docker run -it --rm -v /etc:/hosts-etc --name=lets-mount-etc ubuntu
    
    {title="Query", linenos=off, lang=bash}
        docker inspect -f "{{ json .Mounts }}" lets-mount-etc
    
    {title="Result", linenos=off, lang=bash}
        [
          {
            "Type":"bind",
            "Source":"/etc",
            "Destination":"/hosts-etc",
            "Mode":"",
            "RW":true,
            "Propagation":""
          }
        ]
    
    Also keep in mind that, by default, the user in the container, unless otherwise specified, is root, the same root user as on the host system.
    
    {#vps-identify-risks-docker-docker-host-engine-and-containers-namespaces-mnt-labelling}
    Labelling systems such as [Linux Security Modules (LSM)](#docker-host-engine-and-containers-linux-security-modules) require that the contents of a volume mounted into a container be [labelled](https://docs.docker.com/engine/admin/volumes/volumes/#create-and-manage-volumes). This can be done by adding the `z` (as seen in above example) or `Z` suffix to the volume mount. The `z` suffix instructs Docker to share the mounted volume with other containers, and in so doing, Docker applies a shared content label. Alternatively, if you provide the `Z` suffix, Docker applies a private unshared label, which means only the current container can use the mounted volume. Further details can be found at the [dockervolumes documentation](https://docs.docker.com/engine/admin/volumes/volumes/). This is something to keep in mind if you are using LSM, and have a process inside your container that is unable to use the mounted data.  
    `--volumes-from` allows you to specify a data volume from another container.
    
    You can also [mount](https://linux.die.net/man/8/mount) your Docker container mounts on the host by doing the following:
    
    {linenos=off, lang=bash}
        mount --bind /var/lib/docker/<volumes>/<container id>/_data </path/on/host>  
    
2. `PID`: (Process ID) Provides process isolation, separates container processes from host and other container processes.  
    
    The first process that is created in a new `PID` namespace is the "init" process with `PID` 1, which assumes parenthood of the other processes within the same `PID` namespace. When `PID` 1 is terminated, so are the rest of the processes within the same `PID` namespace.
    
    `PID` namespaces are [hierarchically nested](https://lwn.net/Articles/531419/) in ancestor-descendant relationships to a depth of up to 32 levels. All `PID` namespaces have a parent namespace, other than the initial root `PID` namespace of the host system. That parent namespace is the `PID` namespace of the process that created the child namespace.
    
    Within a `PID` namespace, it is possible to access (make system calls to specific `PID`s) all other processes in the same namespace, as well as all processes of descendant namespaces. However, processes in a child `PID` namespace cannot see processes that exist in the parent `PID` namespace or further removed ancestor namespaces. The direction any process can access another process in an ancestor/descendant `PID` namespace is one way.
    
    Processes in different `PID` namespaces can have the same `PID`, because the `PID` namespace isolates the `PID` number space from other `PID` namespaces.
    
    Docker takes advantage of `PID` namespaces. Just as you would expect, a Docker container can not access the host system processes, and process Ids that are used in the host system can be reused in the container, including `PID` 1, by being reassigned to a process started within the container. The host system can however access all processes within its containers, because as stated above, `PID` namespaces are hierarchically nested in parent-child relationships. Processes in the hosts `PID` namespace can access all processes in their own namespace down to the `PID` namespace that was responsible for starting the process, such as the process within the container in our case.
    
    The default behaviour can however be overridden to allow a container to be able to access processes within a sibling container, or the hosts `PID` namespace. [Example](https://docs.docker.com/engine/reference/run/#pid-settings-pid):
    
    {title="Syntax", linenos=off, lang=bash}
        --pid=[container:<name|id>],[host]
    
    {title="Example", linenos=off, lang=bash}
        # Provides access to the `PID` namespace of container called myContainer
        # for container created from myImage.
        docker run --pid=container:myContainer myImage
    
    {title="Example", linenos=off, lang=bash}
        # Provides access to the host `PID` namespace for container created from myImage
        docker run --pid=host myImage
    
    As an aside, `PID` namespaces give us the [functionality of](http://man7.org/linux/man-pages/man7/pid_namespaces.7.html): "_suspending/resuming the set of processes in the container and migrating the container to a new host while the processes inside the container maintain the same PIDs._" with a [handful of commands](https://www.fir3net.com/Containers/Docker/the-essential-guide-in-transporting-your-docker-containers.html):
    
    {title="Example", linenos=off, lang=bash}
        docker container pause myContainer [mySecondContainer...]
        docker export [options] myContainer
        # Move your container to another host.
        docker import [OPTIONS] file|URL|- [REPOSITORY[:TAG]]
        docker container unpause myContainer [mySecondContainer...]
    
3. `net`: (Networking) Provides network isolation by managing the network stack and interfaces. It's also essential to allow containers to communicate with the host system and other containers. Network namespaces were introduced into the kernel in 2.6.24, January 2008, with an additional year of development they were considered largely done. The only real concern here is understanding the Docker network modes and communication between containers. This is discussed in the Countermeasures.  
      
4. `UTS`: (Unix Timesharing System) Provides isolation of kernel and version identifiers.  
    
    UTS is the sharing of a computing resource with many users, a concept introduced in the 1960s/1970s.
    
    A UTS namespace is the set of identifiers [returned by `uname`](http://man7.org/linux/man-pages/man2/clone.2.html), which include the hostname and the NIS domain name. Any processes which are not children of the process that requested the clone will not be able to see any changes made to the identifiers of the UTS namespace.
    
    If the `CLONE_NEWUTS` constant is set, then the process being created will be created in a new UTS namespace with the hostname and NIS domain name copied and able to be modified independently from the UTS namespace of the calling process.
    
    If the `CLONE_NEWUTS` constant is not set, then the process being created will be created in the same UTS namespace of the calling process, thus able to change the identifiers returned by `uname`.
    
    When a container is created, a UTS namespace is copied ([`CLONE_NEWUTS` is set](https://github.com/docker/libcontainer/blob/83a102cc68a09d890cce3b6c2e5c14c49e6373a0/SPEC.md))(`--uts=""`) by default, providing a UTS namespace that can be modified independently from the target UTS namespece it was copied from.
    
    When a container is created with [`--uts="host"`](https://docs.docker.com/engine/reference/run/#uts-settings-uts), a UTS namespace is inherited from the host, the `--hostname` flag is invalid.  
    
5. `IPC`: (InterProcess Communication) manages access to InterProcess Communications). `IPC` namespaces isolate your container's System V IPC and POSIX message queues, semaphores, and named shared memory from those of the host and other containers, unless another container specifies on run that it wants to share your namespace. It would be a lot safer if the producer could specify which consuming containers could use its [namespace](http://man7.org/linux/man-pages/man7/namespaces.7.html). IPC namespaces do not include IPC mechanisms that use filesystem resources such as named pipes.
    
    According to the [namespaces man page](http://man7.org/linux/man-pages/man7/namespaces.7.html): "_Objects created in an IPC namespace are visible to all other processes that are members of that namespace, but are not visible to processes in other IPC namespaces._"
    
    Although sharing memory segments between processes provide Inter-Process Communications at memory speed, rather than through pipes or worse, the network stack, this produces a significant security concern.
    
    By default a container does not share the host's or any other container's IPC namespace. This behaviour can be overridden to allow a (any) container to reuse another container's or the host's message queues, semaphores, and shared memory via their IPC namespace. [Example](https://docs.docker.com/engine/reference/run/#ipc-settings-ipc):
    
    {title="Syntax", linenos=off, lang=bash}
        # Allows a container to reuse another container's IPC namespace.
        --ipc=[container:<name|id>],[host]
    
    {title="Example", linenos=off, lang=bash}
        docker run -it --rm --name=container-producer ubuntu
        root@609d19340303:/#
        
        # Allows the container named container-consumer to share the IPC namespace
        # of container called container-producer.
        docker run -it --rm --name=container-consumer --ipc=container:container-producer ubuntu
        root@d68ecd6ce69b:/#
    
    Now find the Ids of the two running containers:  
    
    {title="Query", linenos=off, lang=bash}
        docker inspect --format="{{ .Id }}" container-producer container-consumer
    
    {title="Result", linenos=off, lang=bash}
        609d193403032a49481099b1fc53037fb5352ae148c58c362ab0a020f473c040
        d68ecd6ce69b89253f7ab14de23c9335acaca64d210280590731ce1fcf7a7556
    
    You can see from using the command supplied by the [CIS_Docker_1.13.0_Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf) that `container-consumer` is using the IPC namespace of `container-producer`:
    
    {title="Query", linenos=off, lang=bash}
        docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: IpcMode={{ .HostConfig.IpcMode }}'
    
    {title="Result", linenos=off, lang=bash}
        d68ecd6ce69b89253f7ab14de23c9335acaca64d210280590731ce1fcf7a7556: IpcMode=container:container-producer
        609d193403032a49481099b1fc53037fb5352ae148c58c362ab0a020f473c040: IpcMode=
    
    When the last process in an IPC namespace terminates, the namespace will be destroyed along with all IPC objects in the namespace.  
    
6. `user`: Not enabled by default. Allows a process within a container to have a unique range of user and group Ids within the container, known as the subordinate user and group Id feature in the Linux kernel. These do not map to the same user and group Ids of the host, container users to host users are remapped. For example, if a user within a container is root, which it is by default unless a specific user is defined in the image hierarchy, it will be mapped to a non-privileged user on the host system.  
Docker considers user namespaces to be an advanced feature. There are currently some Docker features that are [incompatible](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-user-namespace-options) with using user namespaces, and according to the [CIS Docker 1.13.0 Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf), functionalities that are broken if user namespaces are used. the [Docker engine reference](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-user-namespace-options) provides additional details around known restrictions of user namespaces.  
If your containers have a predefined non-root user, then, currently, user namespaces should not be enabled, due to possible unpredictable issues and complexities, according to "2.8 Enable user namespace support" of the [CIS Docker Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf).  
The problem is that these mappings are performed on the Docker daemon rather than at a per-container level, so it is an all or nothing approach. This may change in the future though.  
As mentioned, user namespace support is available, but not enabled by default in the Docker daemon.
