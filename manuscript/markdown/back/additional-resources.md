# Additional Resources {#additional-resources}

**Cisecurity**  
has an [excellent resource](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf) for hardening docker images, which the Docker Security team helped with. The CIS Benchmark for Docker should be consulted in parallel to reading this book

**I also conducted an interview called "[Docker Security](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/)"**  
for Software Engineering Radio in which Docker Security Team Lead Diogo Monica appeared as guest and provided some excellent advice, opinions, and food for thought, be sure to listen to it

**Network Namespace** source code  
[https://github.com/torvalds/linux/blob/master/net/core/net_namespace.c](https://github.com/torvalds/linux/blob/master/net/core/net_namespace.c)

**IP-NETNS** man page  
[http://man7.org/linux/man-pages/man8/ip-netns.8.html](http://man7.org/linux/man-pages/man8/ip-netns.8.html)

**Introducing Linux Network Namespaces**  
[http://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/](http://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/)

**Network namespaces**  
[https://blogs.igalia.com/dpino/2016/04/10/network-namespaces/](https://blogs.igalia.com/dpino/2016/04/10/network-namespaces/)

**docker network**  
[https://docs.docker.com/engine/reference/commandline/network/](https://docs.docker.com/engine/reference/commandline/network/)

**Namespaces in operation**  
[https://lwn.net/Articles/580893/](https://lwn.net/Articles/580893/)

**dockerscan** may be worth keeping an eye on for offensive testing  
[https://github.com/cr0hn/dockerscan](https://github.com/cr0hn/dockerscan)

**Docker SELinux Man Page**  
[https://www.mankier.com/8/docker_selinux](https://www.mankier.com/8/docker_selinux)

**Increasing Attacker Cost using Immutable Infrastructure**  
https://diogomonica.com/2016/11/19/increasing-attacker-cost-using-immutable-infrastructure/

**Diogo Monica on Mutual TLS**  
[https://www.youtube.com/watch?v=apma_C24W58](https://www.youtube.com/watch?v=apma_C24W58)

**Diogo Monica on Orchestrating Least Privilege**

* [https://www.youtube.com/watch?v=xpGNAiA3XW8](https://www.youtube.com/watch?v=xpGNAiA3XW8)
* https://www.slideshare.net/Docker/orchestrating-least-privilege-by-diogo-monica-6718  
6063

**Comparison of secrets across orchestrators**  
https://medium.com/on-docker/secrets-and-lie-abilities-the-state-of-modern-secret-managem  
ent-2017-c82ec9136a3d#.f6yba66ti

**Description of how PKI automatically gets setup in swarm**  
[https://docs.docker.com/engine/swarm/how-swarm-mode-works/pki/](https://docs.docker.com/engine/swarm/how-swarm-mode-works/pki/)

**Image signing**, and why it is important  
[https://blog.docker.com/2015/08/content-trust-docker-1-8/](https://blog.docker.com/2015/08/content-trust-docker-1-8/)

**Docker security scanning (content integrity)**  
[https://blog.docker.com/2016/05/docker-security-scanning/](https://blog.docker.com/2016/05/docker-security-scanning/)

