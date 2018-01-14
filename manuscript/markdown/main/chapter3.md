# 3. runC and Where it Fits in {#runc-and-where-it-fits-in}

**Docker engine** is now built on containerd and runC. Engine creates the image indirectly via containerd -> runC using [libcontainer](https://github.com/opencontainers/runc/tree/master/libcontainer) -> and passes it to containerd.

[**containerd**](https://containerd.io/) (daemon for Linux or Windows):  
containerd is based on the Docker engine's core container runtime. It manages the complete container life-cycle, managing primitives on Linux and Windows hosts such as the following, whether directly or indirectly:

* Image transfer and storage
* Container execution and supervision
* Management of network interfaces
* Local storage
* Native plumbing level API
* Full Open Container Initiative (OCI) support: image and runtime (runC) specification  

[`containerd`](https://github.com/containerd/containerd) calls `containerd-shim` which uses runC to run the container. `containerd-shim` allows the runtime, which is `docker-runc` in Docker's case, to exit once it has started the container, thus allowing the container to run without a daemon. You can see this if you run  
`ps aux | grep docker`  
In fact, if you run this command you will see how all the components hang together. Viewing this output along with the diagram below, will help solidify your understanding of the relationships between the components.

[**runC**](https://runc.io/) is the container runtime that runs containers (think, run Container) according to the OCI specification, runC is a small standalone command line tool (CLI) built on and providing interface to libcontainer, which does most of the work. runC provides interface with:

* Linux Kernel Namespaces
* Cgroups
* Linux Security Modules
* Capabilities
* Seccomp

These features have been integrated into the low level, light weight, portable, container runtime CLI called runC, with libcontainer doing the heavy lifting. It has no dependency on the rest of the Docker platform, and has all the code required by Docker to interact with the container specific system features. More correctly, libcontainer is the library that interfaces with the above mentioned kernel features. runC leverages libcontainer directly, without the Docker engine being required in the middle.

[runC](https://github.com/opencontainers/runc) was created by the OCI, whose goal is to have an industry standard for container runtimes and formats, attempting to ensure that containers built for one engine can run on other engines.

![](images/DockerArchitecture.png)

## [Using runC Standalone](https://opensource.com/life/16/8/runc-little-container-engine-could)

runC can be [installed](https://docker-saigon.github.io/post/Docker-Internals/#runc:cb6baf67dddd3a71c07abfd705dc7d4b) separately, but it does come with Docker in the form of `docker-runc` as well. Just run it to see the available commands and options.

runC allows us to configure and debug many of the above mentioned points we have discussed. If you want, or need to get to a lower level with your containers, using `runC` (or if you have Docker installed, `docker-runc`), directly can be a useful technique to interact with your containers. It does require additional work that `docker run` commands already do for us. First, you will need to create an OCI bundle, which includes providing configuration for the host independent `config.json` and host specific `runtime.json` [files](https://github.com/containerd/containerd/blob/0.0.5/docs/bundle.md#configs). You must also construct or [export a root filesystem](https://github.com/opencontainers/runc#creating-an-oci-bundle), which if you have Docker installed you can export an existing containers root filesystem with `docker export`. 

A container manifest (`config.json`) can be created by running:  
`runc spec`  
which creates a manifest according to the Open Container Initiative (OCI)/runc specification. Engineers can then add any additional attributes such as capabilities on top of the three specified within a container manifest created by the `runc spec` command.
