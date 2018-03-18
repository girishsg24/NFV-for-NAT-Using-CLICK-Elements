# NFV-for-NAT-Using-CLICK-Elements
1. Developed Virtualized network function foor NAT functionality using minios based vms called clickos.
2. Clickos image provides a NFV framework built on C++ for packet processing functions.
3. Wrote application for NAT and deployed it on a separate VM.
4. I made use of xen hypervisor & open vswitch to connect other similar VNFs together.
5. Using Ovsdb commands, configured flowrules to steer the packet through all the VMS to attain service chaining.

## Video Walkthrough 
Here's a walkthrough of NAT functionality for ICMP packets using CLICKOS :

<img src='https://cloud.githubusercontent.com/assets/22742130/25545707/e4c85e84-2c14-11e7-9a72-ca7962313bb9.gif' title='Video Walkthrough' width='' alt='Video Walkthrough' />

GIF created with [LiceCap](http://www.cockos.com/licecap/).
