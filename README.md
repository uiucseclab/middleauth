# MiddleAuth

This project proposes an immediately deployable system, MiddleAuth, 
for verifying the source address of HTTP/HTTPs traffic 
in the middle of the Internet. 

1. MiddleAuth is immediately deployable since it requires 
no modification on client software, no upgrade for 
Internet routing (e.g., router upgrades or new packet headers) 
and no deployment requirements from unrelated parties (e.g., 
remote ASes that are not commertially related with the service 
provider who wants to deploy MiddleAuth). 

2. MiddleAuth depends on the cloud providers to deploy its 
validation units (called mboxes) to perform source validation in the middle 
of the Internet. MiddleAuth can argument few desireable 
properties for the service provider, such as denying 
undesired traffic early at the cloud to save downstream 
bandwidth for desireable traffic. 

3. MiddleAuth+ is proposed and implemented to prevent 
adversaries from bypassing the mboxes.

4. The design philosopy of MiddleAuth/MiddleAuth+ makes 
the system extensible based on various design goals. 
Can we apply MiddleAuth to solve several practial existing 
security issues? 

