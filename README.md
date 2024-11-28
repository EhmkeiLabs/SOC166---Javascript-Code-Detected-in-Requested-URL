# Walkthrough: Investigation of SOC166 - JavaScript Code Detected in Requested URL  

## Objective 
This lab focuses on identifying and mitigating a **JavaScript injection attack** targeting a webserver. The investigation involved analyzing the payload, determining the source of the malicious activity, and ensuring the attack did not succeed. The goal was to understand the threat, document findings, and improve defenses against similar incidents.

### Skills Learned 
- Log analysis and traffic investigation.  
- Detection and mitigation of XSS (Cross-Site Scripting) attacks.  
- Documentation of Indicators of Compromise (IOCs) for proactive threat defense.  
- Use of threat intelligence platforms like VirusTotal.

### Tools Used  
- Log Management Systems for traffic analysis.  
- Threat Intelligence Platforms (e.g., VirusTotal) to assess IP and domain reputation.  
- Networking tools to trace and validate malicious connections.

## Steps
### Intro to Alert

Lets Grab the Alert Details

	EventID: 116
	Event Time: Feb, 26, 2022, 06:56 PM
	Rule: SOC166 - Javascript Code Detected in Requested URL
	Level: Security Analyst
	Hostname: WebServer1002
	Destination IP: 172.16.17.17
	Source IP: 112.85.42.13
	HTTP Request Method: GET
	Requested URL: https://172.16.17.17/search/?q=<$script>javascript:$alert(1)<$/script>
	User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
	Alert Trigger Reason: Javascript code detected in URL
	Device Action: Allowed


![Image 1](https://i.imgur.com/RN0seFm.png)

### **Case Creation**

Create Case

Start Playbook

![Image 2](https://i.imgur.com/N2rYlH0.png)

![Image 3](https://i.imgur.com/ogw4GxZ.png)

	Q) Why was the alert triggered

Well lets look at our alert details

	A) Rule Trigger Reason: Javascript code detected in URL

 
	Q) Between which two devices is the traffic occuring

Lets look at our Source and Destination IP

Upon putting our Source IP into VirusTotal it  comes back mostly clean but still indicates that the IP may be malicious, we can also see that the IP belongs to a device in China.

![Image 5](https://i.imgur.com/8WqFX8n.png)

Community notes also indicate that this IP was carrying out malicious activities so we can conclude that this is a bad actor. 
![Image 6](https://i.imgur.com/wcA9tuk.png)

Our log details shows that they've made several requests to one of our IPs. Lets see what it is.

![Image 7](https://i.imgur.com/a4HFsME.png)

And of course, it is our webserver. Also noted in the alert details. But we can confirm by looking at our endpoints.

![Image8](https://i.imgur.com/tMu2VW3.png)

	A) Malicious actor (112.85.42.13) -> WebServer1002 (172.16.17.17)

### Collect Data

![Image 8](https://i.imgur.com/D6d5Ivt.png)

	Q) Gather some info to better understand the tradffic.

We will be looking at the details page on VirusTotal of the IP address we scanned


![Image 9](https://i.imgur.com/9GlirNn.png)

	A)
	- Malicious actor (China Unicom Jiangsu province network (112.85.42.13)) ;WebServer1002 (172.16.17.17)
	- Yes traffics coming from internet
	- Likely pooled (dynamic), as it belongs to China Unicom, an ISP ; China Unicom ; No, likely an end-user IP rather than a web hosting service
	- Reputation = Malicious

## Examine Traffic

![Image 10](https://i.imgur.com/gXscNT9.png)

Looking at the log files again we can see the requested URL with the XSS payload

Looks like the request was not responded to

HTTP response 302 also indicates a possible redirect

![Image 11](https://i.imgur.com/VHOrC9a.png)

	Q) HTTP Traffic

	A) 
	- XSS payload (<$script>$for((i)in(self))eval(i)(1)<$/script>)
	- Request method = GET
	- HTTP Response = 0 (Response not returned)
	- HTTP Response Size = 302 (Redirect)

![Image 12](https://i.imgur.com/RmomJ4j.png)

	Q) Traffic Malicious?

	A) Yes

![Image 13](https://i.imgur.com/aghdrsx.png)

	Q) Type of attack
	
	A) XSS


![Image 14](https://i.imgur.com/kkvy8uV.png)

	Q) Is it a planned test?

Because we already determined that it is malicious, we can safely say that it is not planned.

	A) Not planned 


![Image 15](https://i.imgur.com/9qvspLn.png)

	Q) Traffic Direction
	
	A) Internet -> Company Network

![Image 16](https://i.imgur.com/K8oFDC8.png)

	Q) Was Attack Successful?

Because no responses were given by the webserver, we can say that the attack was unsuccessful
![Image 17](https://i.imgur.com/wiUnOdQ.png)

	A) NO

![Image 19](https://i.imgur.com/Po6OpLr.png)

![Image 20](https://i.imgur.com/RTz0wth.png)

	Q) Tier 2 escalation?

	A) NO

## Analyst Note
![Image 21](https://i.imgur.com/9EjhTMA.png)


Finish Playbook

Close Alert

![Image 22](https://i.imgur.com/7ZyxaDq.png)

## Scorecard

We got a perfect score! Im quite happy with this result, determining successful vs unsuccessful XSS attacks can be difficult without being able to see the responses but we were able to accurately conclude what was going on based on our analysis.
![Image 23](https://i.imgur.com/JZEBv8g.png)
