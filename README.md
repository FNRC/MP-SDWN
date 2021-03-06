# MP-SDWN
MP-SDWN is a novel WLAN system based on SDN and NFV, which provide seamless mobility, high throughput and flow-level transmission control for client. 

MP-SDWN is inspired by Odin, and extended it from two main aspects:

1. We add the functions of hostapd into Click to manage the user association with VAP operation. To ultilize the original wireless data frame transmission control algorithm in kernel space, a NAT module is implemented in eth interface to translate the VAP and MAC address of users. (It was finished in release 1.0)

2. A DHCP control model and an access authentication model were implemented in MP-SDWN to provide user access. (It was finished in release 1.0)

3. We proposed MC-VAP (multiple connection supported VAP), for a client, which maintains a same identification distributed on several adjacent physic APs simultaneously, to support multiple-path transmission from multiple APs when client migrates or stays in the wireless signal overlap area. This technology can improve the throughput significantly. (It is still under developing)

## Papers
Our approach is detailed in three scientific contributions:
```
@article{xu2017novel,
  title={A novel multipath-transmission supported software defined wireless network architecture},
  author={Xu, Chuan and Jin, Wenqiang and Zhao, Guofeng and Tianfield, Huaglory and Yu, Shui and Qu, Youyang},
  journal={IEEE access},
  volume={5},
  pages={2111--2125},
  year={2017},
  publisher={IEEE}
}
```
```
@article{wang2017tuna,
  title={Tuna: An efficient and practical scheme for wireless access point in 5G networks virtualization},
  author={Wang, Xinheng and Xu, Chuan and Zhao, Guofeng and Yu, Shui},
  journal={IEEE Communications Letters},
  volume={22},
  number={4},
  pages={748--751},
  year={2017},
  publisher={IEEE}
}
```
```
MC-VAP: A multi-connection virtual access point for high performance software-defined wireless networks
```
