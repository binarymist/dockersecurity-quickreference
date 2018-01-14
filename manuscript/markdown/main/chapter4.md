# 4. Application Security

![](images/ThreatTags/easy-common-easy-moderate.png)

Application security is still our biggest weakness. I cover this in many other places, especially in the Web Applications chapter of my book: Fascicle 1, of [Holistic Info-Sec for Web Developers](https://f1.holisticinfosecforwebdevelopers.com/).

![](images/ThreatTags/PreventionAVERAGE.png)

Yes, container security is important, but in most cases, it is not the lowest hanging fruit for an attacker.

Application security is still the weakest point for compromise. It is usually much easier to attack an application running in a container, or anywhere for that matter, than it is to break container isolation or any security offered by containers and their infrastructure. Once an attacker has exploited any one of the commonly exploited vulnerabilities, such as any of the OWASP Top 10, still being introduced and found in our applications on a daily basis, and subsequently performs remote code execution, then exfils the database, no amount of container security is going to mitigate this.   

During and before my [interview](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) of Diogo Mónica on Docker Security for the Software Engineering Radio show, we discussed isolation concepts, many of which I have covered above. Diogo mentioned: "why does isolation even matter when an attacker already has access to your internal network?" There are very few attacks that require escaping from a container or VM in order to succeed, there are just so many easier approaches to compromise. Yes, this may be an issue for the cloud providers that are hosting containers and VMs, but for most businesses, the most common attack vectors are still attacks focussing on our weakest areas, such as people, password stealing, spear phishing, uploading and execution of web shells, compromising social media accounts, weaponised documents, and ultimately application security, as I have [mentioned many times](https://binarymist.io/talk/js-remote-conf-2017-the-art-of-exploitation/) before.

Diogo and I also had a [discussion](http://www.se-radio.net/2017/05/se-radio-episode-290-diogo-monica-on-docker-security/) about the number of container vs VM vulnerabilities, and it is pretty clear that there are far more vulnerabilities [affecting VMs](https://xenbits.xen.org/xsa/) than there are [affecting containers](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=docker).

VMs have memory isolation, but many of the bugs listed in the [Xen CVEs](https://xenbits.xen.org/xsa/) alone circumvent memory isolation benefits that VMs may have provided.

Another point that Diogo raised was the ability to monitor, inspect, and control the behaviour of applications within containers. In VMs there is so much activity that is unrelated to your applications, so although you can monitor activity within VMs, the noise to signal ratio is just too high to get accurate indications of what is happening in and around your application that actually matters to you. VMs also provide very little ability to control the resources associated with your running application(s). Inside of a container, you have your application and hopefully little else. With the likes of [Control Groups](#hardening-docker-host-engine-and-containers-control-groups-countermeasures) you have many points at which you can monitor and control aspects of the application environment.

As mentioned above, Docker containers are immutable, and can be run read-only.

The Secure Developer podcast with Guy Podjarny interviewing Ben Bernstein (CEO and founder of [Twistlock](#hardening-docker-host-engine-and-containers-twistlock)) - [show #7 Understanding Container Security](http://www.heavybit.com/library/podcasts/the-secure-developer/ep-7-understanding-container-security/) also echo's these same sentiments.

Also be sure to check the [Additional Resources](#additional-resources) chapter for many excellent resources I collected along the way on Docker security.
