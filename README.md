# Network-Defense-Essentials-Notes
EC-Council Network Defense Essentials certificate notes and a MindMap preview of the knowledge this course has to offer.

# Network Security

## Network Security Controls

### Information Assurance (IA) Principles

- Confidentiality

  Ensures information isn't disclosed to unauthorized parties

- Availability

  Ensures that information is not modified or tampered with by unauthorized parties

- Integrity

  unsure that information is available to authorized parties without any 	disruption

- Non-repudiation

  Ensures that a party in a communication cannot deny sending the messsage and each action is associated with a user account.

- Authentication

  Ensures the identity of an individual s verified  by the system or service

### technical security controls

- Access controls

  access controle is a selective restriction of access to an asset, system or network.
  it protects the information assets by detrmining who can access what.
  AC mechanismes uses identification, authentication and authorization to restrict or grant access.

	- Terminologies

	  Subject : refers to a particulat user or process that wants to access a resource.
	  Object : this refers to a specefic resource that the user wants to access such as a file or a hardware device.
	  Reference Monitor : checks the access control rule for specefic restrictions.
	  Operation : it represents an action taken by a subject

	- Principles

		- Separation of Duties (SOD)

		  involves a beakdown of the authorization process into various steps.
		  Different privileges are assigned  at each step to the individual subjects requesting for a resource.
		  This ensures that no single individual has the authorization rights to perform all functions simultaneously denies access of all objects to a single individual.

		- Need-To-Know

		  under the need-to-know access control principle, access is provided only to the information that is required for performing a specific task.

		- Principle of least privilege (POLP)

		  Principle of least privilege extends the need-to-know principle in providing access to a system.
		  POLP believes in providing employees a need.
		  it helps an organization by protecting it from malicious behavior, achieving better system stability and system security.

	- AC Models

		- mandatory access control (MAC)

		  Only the administrator/system owners has the rights to assign privileges.
		  It does not permit the end user to decide who can access the information.
		  
		  EX : UAC in windows

		- discretionary access control (DAC)

		  End user has complete access to the information they own.

		- role-based access control (RBAC)

		  Permission are assigned based on user roles.
		  EX : Just Enough Administration (JEA) it gives a specefic user (tech support) access to some operation on some objects.

		- rule-based access control

		  Permissions are assigned to a user role dynamically based on a set of rules defined by the administrator.

- Identity and Access Management (IAM) 

  IAM is reponsible for providing the right access to the right individual at the right time

	- User Identity Management

		- Identity Management

		  User identification involves a method to ensure that an individual holds a valid identity.
		  Examples of user identity includes attributes such as username, account number, user roles...
		  IDM involves storing and managing user attributes in the identity repositories.

		- Identity repository

		  the user repository is a database where attributes related to the user's identities are stored.

	- User Access Management

		- authentication

		  authentication involves validating the identity of an individual with a system, application or network.
		  Types of Authentication :
		  Password Authentication .
		  Smart card auth.
		  Biometric Auth.
		  2FA Auth.
		  Single Sign-On (SSO) Auth.

		- Authorization

		  Authorization involves controlling the access of information for an entity.
		  EG: a user can only read file but not edit or delete it.

			- centralized Authorization

			  Authorization is done using a single centralized Authorization unit.
			  it mantains a single database for Authorizating all the network resources or applications.
			  it's an easy and inexpensive Authorization approach

			- Decentralized Authorization 


			  Each network resource maintains it's own Authorization unit and performs Authorization locally.
			  it maintains its own database for Authorization.
			  it doesn't support SSO.

			- 
Implicit Authorization

			  Users can access the requested resources on behalf of others.
			  the access request goes through a priamry resource to access the requested resource.

			- Explicit Authorization

			  Unlike implicit authorization, explicit requires seperate authorization for each requested resource.
			  it explicitly maintains authorization for each requested object.

		- Accounting

		  accounting is a method of keeping track of user action on the network, it keeps track of who, when and how the users access the network.
		  it helps in identifying authorized and unauthorized actions.
		  the account data can be used for trend analysis, data breach detection, forensics invistigation...

- Auditing
- Security Protocols

	- Radius

	  Remote Authentication dial-in user service.
	  
	  it's an authentication protocol which provides centralized authentication, authorization and accounting for remote servers to communicate with a central server.
	  
	  auth steps:
	  client initiates a connection by sending the access-request packet to server.
	  the server comapres the credentials sent with those stored on DB then it sends "access-accept" or "accept-reject".
	  client sends the accounting-request to the server to specify the accounting information.

	- Tacacs+

	  Terminal Access Controller Access Control System
	  
	  it's a network security protocol used for AAA of network devices such as switches, routers and firewalls.
	  main features:
	  encrypts entire communication so it's sniffing-proof.

	- Kerberos

	  Client : when a user logs in to the workstation a request is sent to the DC which has the role of KDC. it contains a timestamp that's encrypted using a hash drived from the password of the user and the username
	  KDC : looksup the password hash assosiated with the domain user and attempts to decrypt the timestamp. if the decryption is successful and the timestamp is not a duplicate the auth is validated and a reply is sent to the client which contains a session key (since kerberos is stateless) and TGT. the seesion key is encrypted using the uses password (may be decrypted by the client and reused). the TGT is encrypted by a secret key known only by the KDC.
	  Client : ticket granting service request.
	   KDC : ticket granting server reply.
	  client : sends application request application server which includes the username and a timestamp encrypted with the session key assosiated with a service ticket.
	  Application server : server authentication ( granting access after the server assigns appropriate permissions to the user)

	- PGP

	  Pretty Good Privacy
	  
	  it's an asymetric encryption usually used to encrypt emails
	  public ket is used for encryption by anyone.
	  private key is the only way to decrypting an encrypted msg.

	- S/Mime

- Network security Devices

	- Firewall

	  Firewall is a software or a hardware or a combination of both , which is generally used to separate a protected network from an unprotected public network.
	  it monitors and filters the incoming and outgoing traffic of the network and prevents unauthorized access to private networks.

		- Host-Based Firewall

		  it's used to filter inbound and aoutbound traffic of an individual computer on which it's installed.
		  it is a software based firewall.
		  this firewall software come as part of the OS.

		- Network-Based Firewall

		  it's used to filter inbound and outbound traffic from internal LAN.
		  it is a hardware-based firewall.

		- Technologies

		  [tech] [OSI Layer]
		  Packet filtering. (Transport)
		  Stateful Multilayer Inspection.
		  Ciruit-Level Gateway.
		  Application Proxy. (application)
		  Network address translation. (Network)
		  VPN. (Transport)

		- Next Generation Firewall (NGFW)

		  in addition to traditional firewallks NGFW has the ability to inspect traffic based on packet content.
		  
		  NGFW Capabilities:
		  Deep Packet Inspection.
		  Encrypted Traffic Inspection.
		  QoS/Bandwidth management.
		  Threat intelligence integration.
		  integrated IPS
		  Advanced threat protection

		- Deployment and implementation

			- process 

			  Planning
			  organizations must plan their positioning in advance
			  Configuring
			  Involves configuring various componenents and features.
			  Testing
			  Mainly focuses on whether the firewall rules are set according to the actions performed by the firewall
			  Deploying
			  A phased approach to deploy multiple firewalls on a network help detect and resolve issues.
			  Managing and maintaining
			  Includes maintaining the firewall architecture, policie, software and other components deployed on the network.

			- Recommendations

			  Notify the security policy administrator on firewall changes and document them.
			  remove unused or outdated rules 
			  Do not set conflicting rules or eliminate them, if they already exist.
			  use a standard method and workflow for requesting and implementing firewall changes
			  clean up and optimize the firewall rule base
			  schedule regular firewall security audits
			  keep a log of the firewall rules and configuration changes.

		- Tools

			- IPTABLES

			  list existing rules :
			  sudo iptables -L -n -v
			  Block specefic IP :
			  iptables -A INPUT -s 1.1.1.1 -j DROP
			  Filter Non TCP packets:
			  iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
			  Blocking XMAS scan attack : 
			  iptables -A INPUT -p tcp --tcp-flags ALL -j DROP

	- Bastion Host

	  a bastion host is a computer system designed and configured to protect network resources  from attacks.
	  a bastion host is the only host computer on the internet that can be addressed directly  from the public networks.
	  it provides a limited range of services such as website hosting, and mail to ensure security.

		- why a Bastion Host

		  minimize the risk of penetration by intruders.
		  create all the logs which can  be used to identify attack or attempts to attack.
		  in case of an attack, bastion host acts as a scapegoat
		  provide an additional level of security.

		- Types of Bastion Hosts

			- Non-routing dual-homed hosts

			  They operate with multiple network connections, but the network connections don't interact with each other.

			- External Services Hosts

			  Bastion Hosts are visible to everyone making them vulnerable to attack.
			  They require only minimum access privileges to the internal network, providing only a few services.

			- Victime Hosts

			  Victime machines allow any user to login.
			  they are useful in testing new applications whose security flaws are not yet known and to run services which are not secure.

			- One-Box Firewalls

			  if a machine is constructed as a firewall, it's prone to more attacks.
			  the entire site's security relies onthis single machine, so it's necessary to guarantee that this machine is absolutely secure.

	- IDS/IPS

	  an intrusion detection and prevention system is a network security appliance that inspects all inbound and outbound traffic for suspicious patterns that might indicate a network or system security breach.
	  It also checks the network traffic for signatures that match known intrusion patterns.

		- General indications of intrusion 

			- File System Intruision

			  the presence of new/unfamiliar files, or programs.
			  changes in files permissions.
			  unexplained changes in files size.
			  missing files.

			- Network intruisions

			  repeated probes of the available services n your machines
			  connections from unusual locations.
			  repeated login attempts from remote hosts.
			  a sudden influx of log data.

			- System intrusion

			  short on incomplete logs.
			  slow system performance.
			  modifications to system software or configuration files.
			  gaps in system accounting.
			  system crashes or reboots

		- Charachteristics  of a Good IDS solution

		  run continuously with ess human intervention.
		  must be fault tolerant .
		  resistant to subversion.
		  minimal overhead on the system.
		  observe deviations from normal bahavior.
		  tailored to specefic system needs.
		  copes with dynamic system behavior.

		- Tools

			- SNORT

			  open-source network intrusion detection, capable of performing real-time traffic analysis.

			- Suricata

			  Suricata is a robust network threat detection engine capable of real time intrusion detection, inline intrusion prevention, network security monitoring and offline pcap processing.

	- SIEM

	  SIEM performs real time SOC (security operation center) functions like identifying, monitoring, recording...
	  It provides security by tracking suspicious end-user bahvior activities within a real-time IT environment.

		- Tools

			- Splunk

			  An analytics driven SIEM solution that provides you with what you need to detect and respond to internal and external attacks quickly.

### Physical Security             

- Controls

	- Preventive Controls

	  Prevent security violation and enforce various access control mechanisms.
	  Eg : 
	  door lock
	  security guard

	- Detective Controls

	  Detect security violations and record any intrusion attempts
	  Eg : Motion detectors, alarm systems and sensors

	- Detterent Controls

	  used to discourage attackers and send warning messages to the attackers to discourage intruision attempts
	  Eg : Warning signs

	- Recovery Controls

	  Used to recover from security violations and restore information and systems to a persistent state
	  Eg : disaster recovery, backup systems

	- Compensating Controls 

	  used as an alternative control when the intended controls failed or cannot be used.
	  Eg : hot sites, backup power systems

- Security Checklists

  ensure that proper access control method are implemented.
  ensure that sensitive areas are monitored with proper lighting.
  ensure an alaram system is installed for all types of threats, like fire, smoke and electricity.
  ensure an appropriate door lock system is implemented.
  ensure enough security guards are available for physical security.
  ensure the security personnel is given proper training

## Network Defense Approaches

### Preventative approaches

Consist of methods or techniques  that are used to avoid threats or attacks on the network.

### Reactive Approche

consist of methods or techniques that are used to detect attackson the target network.
in this approache the speed of the reaction is what matters

### Retrospective approaches

consist of methods or techniques  that examine  the causes of attacks, contain, remediate and recover from the damage caused by the attack

### Proactive approaches

consist of method or techniques that are used to make informed decisions on potential attakcs on the future on the target network.

## Network Security Practices / Concepts / components

### Network Segmentation

network segmentation is the practice of splitting a network into smaller network segments seperating group of systems that have no interaction with each other.
security benefits :
improved security 
better access control
improved monitoring
improved performance

- Physical Segmentation

  Physical Segmentation is the process of spliting a larger network into smaller physical components.
  This segments can communicate using intermediary devices such as switches, hubs and routers
  physical network segmentation can be an easy approach to devide a network but it is expensive as it occupies more space.

- Logical segmentation

  Logical segmentation utilizes VLANs, which are isolated logically without considering the physical locations of devices.
  Each Vlan si considered an independant logical unit, and the devices within a vlan  communicate as though they are in there own isolated network.
  in this approach, firewalls are shared and switches handle the VLAN infrastructure.
  it is easier to implement and flexible to operate.

### Network Virualization

network virtualization is a process of combining all the available network resources and enabling security professionals to share these resources amongst the network users using a single administrative unit.
Network virtualization enables each user to access available network resources such as files, folder and printers.

### Demilitarized Zone (DMZ)

the DMZ contains the servers that needs to be accessed from an outside network like:
web servers
email servers
DNS servers
DMZ Configurations:
both internal and external networks can connect to the DMZ.
Hosts in the DMZ can connect to external networks
But hosts in the DMZ can't connect to the internal network.

### User Bahavior Analytics (UBA)

UBA is the process of tracking user behavior to detect malicious attacks, potential threats..
it provides advanced threat detection in an organization to monitor specific  behavioral charechteristics of employees.
UBA technologies are designed to identify variations in traffic patterns caused by user bahaviors which can be either disgruntled employees or malicious attackers

### Virtualization

virtualization refers to a software-based virtual representation of an IT infrastructure that includes network, devices, applications, storage ...etc
the virtualization framework divides the physical resources which are traditionally bound to hardware, into multiple individual simulated environments.

- Components

  Hypervisor / VM monitor
  an application or firmware that enables multiple guest operating systems to share a host's hardware resources.
  Guest Machine / VM
  independant instance of an operating system created by VM monitor.
  Host Machine 
  Real physical machine that provides computing resources to support VM.
  Management Server
  Virtualization platform components used to directly manage the VM.
  Management Console
  interface used to access, configure and manage the virtualization product.

- Containers

  Provide OS-Level virtualization.
  Lightweight.
  All containers share the host os.
  requires less memory space.
  Fully isolated (more secure)

	- Types of Containers

	  OS Containers
	  Containers used as an operating system and run multiple services
	  example : LXC, OpenVZ, BDS Jails
	  
	  Application Containers
	  Containers used to run a signle app and contains its dependencies and hardware requirments file
	  Example : Docker, Rocket

	- Tools

		- Docker

		  docker is an open source technology used for developing, packaging and running applications and all its dependencies in the form of containers.
		  Docker provide a platform as a service through OS-level virtualization and delivers containerized software packages.

			- Docker Security

			  avoid exposing the docker daemon socket.
			  Always use trusted docker images.
			  Regularly path the host OS and docker with the latest security updates.
			  limit the capabilities by allowing access only to features required by the container.
			  use linux security modules like seccomp, apparmor and SELinux to gain more control over the processes.
			  enable read-only mode on file systems and volumes.

		- Kubernetes

		  Kubernetes, also known as K8s, is an open-source, portable, extensible, orchestration platform developed by Google for managing containerized applications and microservices.
		  kubernetes provides a resilient framework for managing distributed containers, generating and performing failover and redundancy for the apps.

	- Security threats

		- Image threats

		  Image vulnerabilities.
		  Image configuration defects.
		  Embeded malware.
		  Embeded clear text secrets.
		  Use of untrusted images

		- Registry threats

		  insecure connections to registries.
		  stale images in registries.
		  Insufficient authentication and authorization restrictions.

		- Container threats

		  Vulnerabilities withinthe runtime software.
		  Unbounded network access from containers.
		  Insecure container runtime configurations.
		  app vulnerabilities .
		  rogue containers.

		- Host OS Threats

		  Large attack surface.
		  shared kernel.
		  Host OS component vulnerabilities.
		  Improper used access rights.
		  Host OS file system tampering.

		- Orchestrator threats

		  Unbounded administrative access.
		  Unauthorized access
		  Poorly separated inter-container network traffic.
		  mixing of workload sensitivity levels.
		  Orchestrator node trust.

- Cloud Computing

	- Cloud Security

		- Shared responsability

		  Cloud security and compliance are the shared responsability of the cloud provider and consumer.
		  According to the selected module, security responsabilities are devided based on the shared responsability model.
		  if the consumer do not secure their functions, the entire cloud security model will fail.

			- Cloud service consumers

			  User security and monitoring (IAM).
			  information security-data .
			  application level security.
			  data storage security.
			  monitoring, logging and compliance.

			- Cloud service providers

			  cloud service providers are responsible for securing infrastructure, including routers, switches, load balancers, firewalls, hypervisors....

		- Compliance

		  a clear idea about the regulation standards that an organization wants to comply with along with its associated requirements allows organizations benefit from the business agility and growth.

		- Logging

		  security logs are used for threat detection, data analysis, and compliance audits to enhance cloud security.
		  Efficient security log management for cloud includes aggregating all logs, capturing appropriate data, controlling log collection and distribution frequency, ensuring scalability ...

		- Best Practices

		  Enforce data protection, backup and retention mechanisms.
		  Enforce SLAs for patching and vulnerability remediation.
		  Vendors should regularly undergo AICPA SAS 70 Type 2 audits.
		  Enforce legal contracts in employee behavior policy.
		  Prohibit user credential sharing among users, services or applications.
		  implement strong authentication, authorization and auditing controls.
		  Check for data protection at both the design stage and at runtime.

	- Storage Achitechture

		- Front End

		  the front end layer is accessed by the end user where it provides APIs for the managment of data storage.

		- Middleware

		  The middleware layer performs several functions such as data de-duplication and replication of data.

		- Back End

		  the Back end layer is where the hardware is implemented

- Virtual Machines

  Provides hardware-level virtualization.
  Heavyweight
  Each virtual machine run in its own OS.
  Allocates required memory.
  Process-Level isolation (less secure)

- Security Best practices

  regularly monitor the CVEs of the container runtime.
  Employ app-aware tools to monitor container network interfaces and traffic.
  Configure apps to run as a non-privileged user to avoid privilege escalation.
  Configure the host's root file system in read-only mode to restrict the write accesss.
  Employ application security scanning tools.
  perform regular scanning of the images in the repository to identify vulnerabilities or misconfigurations.

## Regulatory Frameworks Compliance

Why Organizations Need Compliance?
improves Security
Minimize Losses

### Regulatory Frameworks

Framework : Health Inssurance Portability and Accountability Act (HIPAA).
Scope : any company or office that deals with healthcare data.
===========
Framework : Federal information Security Management Act of 2002 (FISMA).
Scope :  All Federal agencies must develop a method of protecting information systems.
===========
Framework : Gram leach Bliley Act (GLBA).
Scope :  Companies that offer financial products or services to individuals. 
===========
Framework : Payment Card Industry Data Security Standards. (PCI-DSS)
Scope :  companies handling credit card infos.

### Policies

what is a security policy?
a security policy is a zell-document set of plans, procedures and standards required to establish and maintain an ideal security status for an org.
security policies are used to inform people on how to work in a safe and secure manner.
the security policy is an integral part of an information security management program.

Example : encryption policy

- Entreprise Information Security Policy (EISP)

  EISP drives an organization's scope and profvdes direction to their security policies.
  examples : 
  aaplication policy
  network and network device security policy
  back up and restore policy
  system security policy

- Issue Specefic Security Policy (ISSP)

  ISSP directs the audience on the usage of technology-based systems with the help of guidlines.
  Examples : 
  Remote access and wireless policies
  incident response plan
  password policies
  policies for personal devices

- System Specific Security Policy

  SSSP directs users while configuring or maintaining a system.
  Examples:
  DMZ Policy
  Encryption Policy
  Policies for intruision detection and prevention
  access control policy

- Internet Access Policies

	- promiscuous policy

	  No restriction on internet/remote access
	  nothing is Blocked.

	- Permissive Policy

	  Known dangerous services/attacks blocked.
	  policy begins with no restrictions
	  known holes plugged and known dangers stopped.

	- Paranoid Policy

	  Everything is forbidden
	  no internet connection, or severely limited internet usage.
	  users find ways around overly severe restrictions.

	- Prudent Policy

	  provides maximum security while allowing known, but necessary dangers.
	  all services are blocked
	  safe/necessary services are allowed individually.

- Paasword Policy

  password length and formation.
  complexity of password.
  password blacklists.
  password duration.
  common password practice.

### Standards

Example :  encryption standards such as data encryption standards (DES), Advanced encryption standards (AES) and Rivest-Shamir-Adleman (RSA)

### Procedurs, Practices, Guidlines

Example : Data encryption procedures, practices and guidlines.

- Employee Awareness and training

  An organization need to provide formal security awareness and training, so employees can :
  know ho to defend themselves and the org against threats.
  follow security policies and procedures for working with it.
  kno whom to contact if they discover a sec threat.
  can identify the nature of the data based on data classification.
  protect physical and informational assets of that org.

## Network Defense Challenges 

### Distributed Computing Environments

with the modern technology advancement, netowrks are becoming much more vast and complex potentially leading to serious security vulnerabilities.

### Emerging Threats

Potential threats to the network evolve each day. network attacks are becoming more sofisticated and better organized.

### Lack of Network Security Skills

## Wireless Network Security

### Wireless Terminologie

GSM : a universal system used for mobile transportation for wireless networks worldwide.
Bandwidth :  Describes the ammount of information that can be broadcasted over a connection
AP : access point, used to connect wireless devices to wireless/wired network.
BSSID : The mac address of an ap that has set up a basic service set.
SSID : A unique identifier of 32 chars given to a wireless local area network (WLAN).
ISM Band : A set of frequencies for the international industrial, scientific and medical communities.
HOTSPOT : A place where a wireless network is available for public use.
OFDM : Orthogonal Frequency-Division Multiplexing is a method of encoding digital data on multiple carrier frequencies.
DSSS : Direct Sequence Spread Spectrum, na original data signal multiplied with a pseudo-random noise spreading the code.

### Wireless Technologies

WIFI : it uses radio waves or microwaves to allow electronic devices to exchange data or connect to the internet.
Bluetooth : using bluetooth technology, data is transmitted between cell phones, computers and other networking devices over short distances.
RFID : it uses radio frequency (RF) electromagnetic waves to transfer data for automatic identification and for tracking tags attached to objects.
WIMAX : it uses long distance wireless networking and high speed internet and belongs to IEEE 802.16 family of wireless networking standards.

### Wireless Network Components

AP : it is a hardware device that allows wireless communication devices to connect to a wireless network via wireless standards such as bluetooth, wifi ....
Wireless Cards (NIC) : system connected to the wireless network require a network interface cards (NIC) to establish a standard ethernet connection.
Wireless modem : it is a device that receives and transmits netowkr signals to other units ithout requiring physical cabling.
Wireless Bridge : it connects multiple LANs at the medium access control (MAC) layer and is separated either logically or physically, it's used for increasing the coverage area of the wireless network.
Router : performs the function of a router as well as a wireless AP and provides internet access to various devices.

### Wireless Encryption

802.11i : An IEEE amendment that specifies security mechanisms for 802.11 wireless networks.
WEP : an encryption algorithm for IEEE 802.11 wireless networks.
EAP : Supports multiple authentication methods, such as token cards, kerberos and certificats.
LEAP : a proprietary version of EAP developed by cisco.
WPA : An advanced wireless encryption protocol using TKIP and MIC to provide stronger encryption and authentication.
TKIP : A security protocol used in WPA as a replacement for wep.
WPA2 : An upgrade to WPA using AES and CCMP for wireless data encryption.
AES : A symmetric-key encryption, used in WPA2 as a replacement for TKIP.
CCMP : An encryption protocol used in WPA2 for stronger encryption and authentication.

- Security issues

  Issues in WEP :
  CRC-32 does not ensure complete cryptographic integrity.
  IVs are 24 bits and sent in cleartext.
  Vulnerable to known plain-text attacks.
  Prone to password cracking attacks.
  Lack of centralized key management. 
  Issues in WPA :
  Pre-shared key is vulnerable to evasedropping and dictionary attacks.
  Lack of forward secrecy.
  WPA-TKIP is vulnerable to packet spoofing and decryption attacks.
  Insecure random number generator (RNG) in WPA allows to discover GTK generated by AP.
  Vulnerabilities in TKIP allow attackers to guess the IP Address of the subnet.
  Issues in WPA2:
  Pre-shared key is vulnerable to evasedropping and dictionary attacks.
  Lack  of forwaard secrecy.
  Hole96 vulnerabilities make WPA2 vulnerable to MITM and DOS attacks.
  Insecure randome number generator (RNG) in WPA2 allow attackers to discover GTK generated by AP.
  KRACK vulnerabilities make WPA2 vulnerable to packet sniffing, connection hijacking, malware injection and decryption attacks.

### Network Security Measures

Create an inventory of wireless devices.
Placement of the wireless AP and antenna.
Disable SSID broadcasting.
Select a strong wireless encryption mode.
Defend against WPA cracking.
Detect rogue APs.
Locate rogue APs.
Configure the security on wireless routers.

## Data Security

Data is the organization's ultimate asset, which attackers may be interessted in.
if an organization's data is exposed or lost by any means, it can severely damage business and reputation.

### States of Digital Data

- Data at rest

  inactive data stored digitally at a physical location.

	- Security controls

	  Data encryption.
	  Password protection.
	  Tokenization.
	  Data federation.

- Data in use

  Data stored in memory.

	- Security controls

	  Authentication techniques.
	  Tight control on this data's accessibility.
	  full memory encryption.
	  Strong identity management.

- Data in transit

  Data traversing using some means of communication.

	- Security controls

	  SSL and TLS.
	  Email encryption tools such as PGP or S/MIME.
	  Firewall controls.

### Data security technologies

Data access control
Data encryption
Data Masking (protecting information by obscuring specfic areas of data with random chars or code)
Data resilience and backup
Data destruction
Data retention

### Data Backup Strategy/Plan

Identifying the critical business data.
selecting the backup media.
selecting a backup technology.
selecting the appropriate RAID levels.
Selecting an appropriate backup method.
selecting the backup types.
choosing the right backup solution.
conducting a recovery drill test.

### Data loss prevention (DLP)

data loss prevention includes a set of software products and processes that do not allow users to send confidential corporate data outside the organization.

- Endpoint DLP

  a solution that monitors and protects PC-based systems such as tablets, laptops...
  It is used for preventing data leakage through clipboards, removable devices and sharing apps.

- Network DLP

  A solution that monitors, protects and reports alldata in transit.
  it is installed at the perimiter of an organization network.
  It helps the security professionals in scanning all data moving through the ports and protocols within the organization.

- Storage DLP

  A solution that monitors and protects data at rest, that is, the data stored in an organization's data center infrastructure such as fileservers, sharepoint and databases.
  it identifies the location where sensitive information is stored and helps users in determining  whether it is stored securely.

