# 1. Habitat

With the continual push for shorter development cycles, combined with continuous delivery, as well as cloud and virtual based infrastructure, containers have become an important part of the continuous delivery pipeline. Docker has established itself as a top contender in this space.

Many of Docker's defaults favour ease of use over security, in saying that, Docker's security considerations follow closely. After working with Docker, the research I have performed in writing these sections on Docker security, while having the chance to [discuss](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) many of my concerns and ideas with the Docker Security team lead, Diogo Mónica, it is my belief that, by default, Docker containers, infrastructure and orchestration provide better security than running your applications in Virtual Machines (VMs). Just be careful when comparing containers with VMs, as this is analogous with comparing apples to oranges.

Docker security provides immense configurability to improve its security posture many times over better than defaults. In order to do this properly, you will have to invest some time and effort into learning about the possible issues, features, and how to configure them. I have attempted to illuminate this specifically in these sections on Docker security.

Docker security is similar to VPS security, except there is a much larger attack surface. This is most noteworthy when running many containers with different packages, many of which do not receive timely security updates, as noted by [banyan](https://www.banyanops.com/blog/analyzing-docker-hub/) and [the morning paper](https://blog.acolyer.org/2017/04/03/a-study-of-security-vulnerabilities-on-docker-hub/).

A monolithic kernel, such as the Linux kernel, which contains tens of millions of lines of code, and can be reached by untrusted applications via all sorts of networking, USB, and driver APIs, has a huge attack surface. Adding Docker into the mix has the potential to expose all these vulnerabilities to each and every running container, and its applications within, thus making the attack surface of the kernel grow exponentially.

Docker leverage's many features that have been in the Linux kernel for years, which provide many security enhancements out of the box. The Docker Security Team are working hard to add additional tooling and techniques to further harden their components, this has become obvious as I have investigated many of them. You still need to know what all the features, tooling and techniques are, and how to use them, in order to determine whether your container security is adequate for your needs.

From the [Docker overview](https://docs.docker.com/engine/docker-overview/), it states: “_Docker provides the ability to package and run an application in a loosely isolated environment_”. Later in the same document it says: "_Each container is an isolated and secure application platform, but can be given access to resources running in a different host or container_" leaving the "loosely" out. It continues to say: “_Encapsulate your applications (and supporting components) into Docker containers_”. The meaning of encapsulate is to enclose, but if we are only loosely isolating, then we're not really enclosing are we? I will address this concern in the following Docker sections and subsections.

To start with, I am going to discuss many areas where we can improve container security. At the end of this Docker section I will discuss why application security is of far more concern than container security.

It is my intent to provide a high level over view of the concepts you will need to know in order to create a secure environment for the core Docker components, and your containers. There are many resources available, and the Docker security team is hard at work constantly trying to make the task of improving security around Docker easier.

Do not forget to check the [Additional Resources](#additional-resources) section for material to be consumed in parallel with the Docker Countermeasures, such as the excellent CIS Docker Benchmark, and the [interview](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) I conducted with the Docker Security Team Lead Diogo Mónica.

CISecurity has an [excellent resource](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf) for hardening docker images, which the Docker Security team helped with.

## Consumption from [Registries](https://docs.docker.com/registry/)
![](images/ThreatTags/average-verywidespread-easy-moderate.png)

This is a similar concept to that of consuming free and open source, which the OWASP [A9 (Using Components with Known Vulnerabilities)](https://www.owasp.org/index.php/Top_10_2017-A9-Using_Components_with_Known_Vulnerabilities) addresses. Many of us trust the images on Docker hub without much consideration for the possibly defective packages within. There have been quite a few reports with varying numbers of vulnerable images as noted by Banyan and "the morning paper" mentioned above.

The Docker Registry [project](https://github.com/docker/distribution) is an open-source server side application that lets you store and distribute Docker images. You could run your own registry as part of your organisation's Continuous Integration (CI) / Continuous Delivery (CD) pipeline. Some of the public known instances of the registry are:

* [Docker Hub](https://hub.docker.com/explore/)
* EC2 Container Registry
* Google Container Registry
* CoreOS quay.io

![](images/ThreatTags/PreventionAVERAGE.png)

"_Docker Security Scanning is available as an add-on to Docker hosted private repositories on both Docker Cloud and Docker Hub._". You also have to [opt in](https://docs.docker.com/docker-cloud/builds/image-scan/#/opt-in-to-docker-security-scanning) and pay for it. Docker Security Scanning is also now available on the new [Enterprise Edition](https://blog.docker.com/2017/03/docker-enterprise-edition/). The scan compares the SHA of each component in the image with those in an up to date CVE database for known vulnerabilities. This is a good start, but not free and does not do enough. Images are scanned on push and the results indexed so that when new CVE databases are available, comparisons can continue to be made.

It's up to the person consuming images from docker hub to assess whether or not they have vulnerabilities. Whether unofficial or [official](https://github.com/docker-library/official-images), it is your responsibility. Check the [Hardening Docker Host, Engine and Containers](#hardening-docker-host-engine-and-containers) section for tooling to assist with finding vulnerabilities in your Docker hosts and images.

Your priority before you start testing images for vulnerable contents, is to understand the following:

1. Where your image originated from
2. Who created it
3. Image provenance: Is Docker fetching the [image](https://docs.docker.com/engine/docker-overview/#docker-objects) we think it is?
    1. Identification: How Docker uses secure hashes, or digests.  
    Image layers (deltas) are created during the image build process, and also when commands within the container are run, which produce new or modified files and/or directories.  
    Layers are now identified by a digest which looks like:
    `sha256:<the-hash>`  
    The above hash element is created by applying the SHA256 hashing algorithm to the layers content.  
    The image ID is also the hash of the configuration object which contains the hashes of all the layers that make up the images copy-on-write filesystem definition, also discussed in my [Software Engineering Radio show](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) with Diogo Mónica.
    2. Integrity: How do you know that your image has not been tampered with?  
    This is where secure signing comes in with the [Docker Content Trust](https://blog.docker.com/2015/08/content-trust-docker-1-8/) feature. Docker Content Trust is enabled through an integration of [Notary](https://github.com/theupdateframework/notary) into the Docker Engine. Both the Docker image producing party and image consuming party need to opt-in to use Docker Content Trust. By default, it is disabled. In order to do that, Notary must be downloaded and setup by both parties, and the `DOCKER_CONTENT_TRUST` environment variable [must be set](https://docs.docker.com/engine/security/trust/content_trust/#/enable-and-disable-content-trust-per-shell-or-per-invocation) to `1`, and the `DOCKER_CONTENT_TRUST_SERVER` must be [set to the URL](https://docs.docker.com/engine/reference/commandline/cli/#environment-variables) of the Notary server you setup.  
    
        Now the producer can sign their image, but first, they need to [generate a key pair](https://docs.docker.com/engine/security/trust/trust_delegation/). Once they have done so, when the image is pushed to the registry, it is signed with their private (tagging) key.
        
        When the image consumer pulls the signed image, Docker Engine uses the publisher's public (tagging) key to verify that the image you are about to run is cryptographically identical to the image the publisher pushed.
        
        Docker Content Trust also uses the Timestamp key when publishing the image, this makes sure that the consumer is getting the most recent image on pull.
        
        Notary is based on a Go implementation of [The Update Framework (TUF)](https://theupdateframework.github.io/)  
        
    3. By specifying a digest tag in a `FROM` instruction in your `Dockerfile`, when you `pull` the same image will be fetched.

## Doppelganger images
![](images/ThreatTags/average-common-average-severe.png)

Beware of doppelganger images that will be available for all to consume, similar to doppelganger packages that I discuss in the Web Applications chapter of Fascicle 1 of my book [Holistic Info-Sec for Web Developers](https://f1.holisticinfosecforwebdevelopers.com/) . These can contain a huge number of packages and code that can be used to hide malware in a Docker image.

People often miss-type what they want to install. Attackers often take advantage of this by creating malicious packages with very similar names. Some of the actions could be: having consumers of your package destroy or modify their systems, send sensitive information to the attacker, or any number of other malicious activities.

![](images/ThreatTags/PreventionAVERAGE.png)

If you are already performing the last step from above, then fetching an image with a very similar name becomes highly unlikely, but it pays to be aware of these types of techniques that attackers use.

