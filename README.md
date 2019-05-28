# MP-SDWN
MP-SDWN is a novel WLAN system based on SDN and NFV, which provide seamless mobility, high throughput and flow-level transmission control for client. 

MP-SDWN is inspired by Odin, and extended it from two main aspects:

1. We add the functions of hostapd into Click to manage the user association with VAP operation. To ultilize the original wireless data frame transmission control algorithm in kernel space, a NAT module is implemented in eth interface to translate the VAP and MAC address of users. (It was finished in release 1.0)

2. A DHCP control model and an access authentication model were implemented in MP-SDWN to provide user access. (It was finished in release 1.0)

3. We proposed MC-VAP (multiple connection supported VAP), for a client, which maintains a same identification distributed on several adjacent physic APs simultaneously, to support multiple-path transmission from multiple APs when client migrates or stays in the wireless signal overlap area. This technology can improve the throughput significantly. (It is still under developing)

Our approach is detailed in three scientific contributions:
