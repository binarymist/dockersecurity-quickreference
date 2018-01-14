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
    This is where secure signing comes in with the [Docker Content Trust](https://blog.docker.com/2015/08/content-trust-docker-1-8/) feature. Docker Content Trust is enabled through an integration of [Notary](https://github.com/theupdateframework/notary) into the Docker Engine. Both the Docker image producing party and image consuming party need to opt-in to use Docker Content Trust. By default, it is disabled. In order to do that, Notary must be downloaded and setup by both parties, and the `DOCKER_CONTENT_TRUST` environment variable [must be set](https://docs.docker.com/engine/security/trust/content_trust/#enable-and-disable-content-trust-per-shell-or-per-invocation) to `1`, and the `DOCKER_CONTENT_TRUST_SERVER` must be [set to the URL](https://docs.docker.com/engine/reference/commandline/cli/#environment-variables) of the Notary server you setup.  
    
        Now the producer can sign their image, but first, they need to [generate a key pair](https://docs.docker.com/engine/security/trust/trust_delegation/). Once they have done so, when the image is pushed to the registry, it is signed with their private (tagging) key.
        
        When the image consumer pulls the signed image, Docker Engine uses the publisher's public (tagging) key to verify that the image you are about to run is cryptographically identical to the image the publisher pushed.
        
        Docker Content Trust also uses the Timestamp key when publishing the image, this makes sure that the consumer is getting the most recent image on pull.
        
        Notary is based on a Go implementation of [The Update Framework (TUF)](https://theupdateframework.github.io/)  
        
    3. By specifying a digest tag in a `FROM` instruction in your `Dockerfile`, when you `pull` the same image will be fetched.

## Doppelganger images
![](images/ThreatTags/average-common-average-severe.png)

Beware of doppelganger images that will be available for all to consume, similar to doppelganger packages that I discuss in the Web Applications chapter of Fascicle 1 of my book [Holistic Info-Sec for Web Developers](https://f1.holisticinfosecforwebdevelopers.com/), these can contain a huge number of packages and code that can be used to hide malware in a Docker image.

People often miss-type what they want to install. Attackers often take advantage of this by creating malicious packages with very similar names. Some of the actions could be: having consumers of your package destroy or modify their systems, send sensitive information to the attacker, or any number of other malicious activities.

![](images/ThreatTags/PreventionAVERAGE.png)

If you are already performing step 3 from above, then fetching an image with a very similar name becomes highly unlikely, but it pays to be aware of these types of techniques that attackers use.

## The Default User is Root {#the-default-user-is-root}
![](images/ThreatTags/easy-common-veryeasy-moderate.png)

What is worse, Docker's default is to run containers, and all commands / processes within a container as root. This can be seen by running the following command from the [CIS_Docker_1.13.0_Benchmark](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf):

{title="Query User running containers", linenos=off, lang=Bash}
    docker ps --quiet | xargs docker inspect --format '{{ .Id }}: User={{ .Config.User }}'

If you have two containers running, and the user has not been specified, you will see something like the below, which means your two containers are running as root.

{title="Result of user running containers output", linenos=off, lang=Bash}
    <container n Id>: User=
    <container n+1 Id>: User=

Images derived from other images inherit the same user defined in the parent image explicitly or implicitly, so unless the image creator has specifically defined a non-root user, the user will default to root. That means all processes within the container will run as root.

![](images/ThreatTags/PreventionVERYEASY.png)

In order to run containers as a non-root user, the user needs to be added in the base image (`Dockerfile`) if it is under your control, and set before any commands you want run as a non-root user. Here is an example of the [NodeGoat](https://github.com/owasp/nodegoat) image:

{title="NodeGoat Dockerfile", linenos=on}
    FROM node:4.4
    
    # Create an environment variable in our image for the non-root user we want to use.
    ENV user nodegoat_docker
    ENV workdir /usr/src/app/
    
    # Home is required for npm install. System account with no ability to login to shell
    RUN useradd --create-home --system --shell /bin/false $user
    
    RUN mkdir --parents $workdir
    WORKDIR $workdir
    COPY package.json $workdir
    
    # chown is required by npm install as a non-root user.
    RUN chown $user:$user --recursive $workdir
    # Then all further actions including running the containers should
    # be done under non-root user, unless root is actually required.
    USER $user
    
    RUN npm install
    COPY . $workdir
    
    # Permissions need to be reapplied, due to how docker applies root to new files.
    USER root
    RUN chown $user:$user --recursive $workdir
    RUN chmod --recursive o-wrx $workdir
    
    RUN ls -liah
    RUN ls ../ -liah
    USER $user

As you can see on line 4 we create our `nodegoat_docker` user.  
On line 8 we add our non-root user to the image with no ability to login.  
On line 15 we change the ownership of the `$workdir` so our non-root user has access to do the things that we normally have permissions to do without root, such as installing npm packages and copying files, as we see on line 20 and 21. But first we need to switch to our non-root user on line 18. On lines 25 and 26 we need to reapply ownership and permissions due to the fact that docker does not `COPY` according to the user you are set to run commands as.

Without reapplying the ownership and permissions of the non-root user as seen above on lines 25 and 26, the container directory listings would look like this:

{title="No reapplication of ownership and permissions", linenos=off}
    Step 12 : RUN ls -liah
     ---> Running in f8692fc32cc7
    total 116K
    13 drwxr-xr-x   9 nodegoat_docker nodegoat_docker 4.0K Sep 13 09:00 .
    12 drwxr-xr-x   7 root            root            4.0K Sep 13 09:00 ..
    65 drwxr-xr-x   8 root            root            4.0K Sep 13 08:59 .git
    53 -rw-r--r--   1 root            root             178 Sep 12 04:22 .gitignore
    69 -rw-r--r--   1 root            root            1.9K Nov 21  2015 .jshintrc
    61 -rw-r--r--   1 root            root              55 Nov 21  2015 .nodemonignore
    58 -rw-r--r--   1 root            root             715 Sep 13 08:59 Dockerfile
    55 -rw-r--r--   1 root            root            6.6K Sep 12 04:16 Gruntfile.js
    60 -rw-r--r--   1 root            root             11K Nov 21  2015 LICENSE
    68 -rw-r--r--   1 root            root              48 Nov 21  2015 Procfile
    64 -rw-r--r--   1 root            root            5.6K Sep 12 04:22 README.md
    56 drwxr-xr-x   6 root            root            4.0K Nov 21  2015 app
    66 -rw-r--r--   1 root            root             527 Nov 15  2015 app.json
    54 drwxr-xr-x   3 root            root            4.0K May 16 11:41 artifacts
    62 drwxr-xr-x   3 root            root            4.0K Nov 21  2015 config
    57 -rw-r--r--   1 root            root             244 Sep 13 04:51 docker-compose.yml
    67 drwxr-xr-x 498 root            root             20K Sep 12 03:50 node_modules
    63 -rw-r--r--   1 root            root            1.4K Sep 12 04:22 package.json
    52 -rw-r--r--   1 root            root            4.6K Sep 12 04:01 server.js
    59 drwxr-xr-x   4 root            root            4.0K Nov 21  2015 test
     ---> ad42366b24d7
    Removing intermediate container f8692fc32cc7
    Step 13 : RUN ls ../ -liah
     ---> Running in 4074cc02dd1d
    total 12K
    12 drwxr-xr-x  7 root            root            4.0K Sep 13 09:00 .
    11 drwxr-xr-x 32 root            root            4.0K Sep 13 09:00 ..
    13 drwxr-xr-x  9 nodegoat_docker nodegoat_docker 4.0K Sep 13 09:00 app

With reapplication of the ownership and permissions of the non-root user, as the `Dockerfile` is currently above, the container directory listings look like the following:

{title="With reapplication of ownership and permissions", linenos=off}
    Step 15 : RUN ls -liah
     ---> Running in 8662e1657d0f
    total 116K
    13 drwxr-x---   21 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 .
    12 drwxr-xr-x    9 root            root            4.0K Sep 13 08:51 ..
    65 drwxr-x---   20 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 .git
    53 -rw-r-----    1 nodegoat_docker nodegoat_docker  178 Sep 12 04:22 .gitignore
    69 -rw-r-----    1 nodegoat_docker nodegoat_docker 1.9K Nov 21  2015 .jshintrc
    61 -rw-r-----    1 nodegoat_docker nodegoat_docker   55 Nov 21  2015 .nodemonignore
    58 -rw-r-----    1 nodegoat_docker nodegoat_docker  884 Sep 13 08:46 Dockerfile
    55 -rw-r-----    1 nodegoat_docker nodegoat_docker 6.6K Sep 12 04:16 Gruntfile.js
    60 -rw-r-----    1 nodegoat_docker nodegoat_docker  11K Nov 21  2015 LICENSE
    68 -rw-r-----    1 nodegoat_docker nodegoat_docker   48 Nov 21  2015 Procfile
    64 -rw-r-----    1 nodegoat_docker nodegoat_docker 5.6K Sep 12 04:22 README.md
    56 drwxr-x---   14 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 app
    66 -rw-r-----    1 nodegoat_docker nodegoat_docker  527 Nov 15  2015 app.json
    54 drwxr-x---    5 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 artifacts
    62 drwxr-x---    5 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 config
    57 -rw-r-----    1 nodegoat_docker nodegoat_docker  244 Sep 13 04:51 docker-compose.yml
    67 drwxr-x--- 1428 nodegoat_docker nodegoat_docker  20K Sep 13 08:51 node_modules
    63 -rw-r-----    1 nodegoat_docker nodegoat_docker 1.4K Sep 12 04:22 package.json
    52 -rw-r-----    1 nodegoat_docker nodegoat_docker 4.6K Sep 12 04:01 server.js
    59 drwxr-x---    8 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 test
     ---> b88d816315b1
    Removing intermediate container 8662e1657d0f
    Step 16 : RUN ls ../ -liah
     ---> Running in 0ee2dcc889a6
    total 12K
    12 drwxr-xr-x  9 root            root            4.0K Sep 13 08:51 .
    11 drwxr-xr-x 34 root            root            4.0K Sep 13 08:51 ..
    13 drwxr-x--- 21 nodegoat_docker nodegoat_docker 4.0K Sep 13 08:51 app

An alternative to setting the non-root user in the `Dockerfile` is to set it in the `docker-compose.yml`, provided that the non-root user has been added to the image in the `Dockerfile`. In the case of NodeGoat, the mongo `Dockerfile` is maintained by DockerHub, and it adds a user called `mongodb`. In the NodeGoat projects `docker-compose.yml`, we just need to set the user, as seen on line 13 below:

{id="nodegoat-docker-compose.yml", title="NodeGoat docker-compose.yml", linenos=on}
    version: "2.0"
    
    services:
      web:
        build: .
        command: bash -c "node artifacts/db-reset.js && npm start"
        ports:
          - "4000:4000"
        links:
          - mongo
      mongo:
        image: mongo:latest
        user: mongodb
        expose:
          - "27017"

Alternatively, a container may be run as a non-root user by  
`docker run -it --user lowprivuser myimage`  
but this is not ideal, the specific user should usually be part of the build.


