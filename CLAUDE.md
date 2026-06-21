
This project is for creating both a generic "Web Application And API Firewall" Framework AND individual application firewall configurations for Openresty.


I have roughly thrown together proof-of-concept configurations for:
	* Jellyfin Media server's web portal
	* MediaWiki's web portal
That implementation is rough and not complete, but it does work well in a home lab environment.


See the files in ./rootfs/ for that implementation:

jeremy@thinkpadx1gen6 ~/code/openresty-waaapi-firewall $ tree -s rootfs/
[          4]  rootfs/
├── [          3]  etc
│   └── [          3]  openresty
│       └── [       4939]  api_policy_handler_jellyfin.lua
└── [          3]  usr
    └── [          3]  local
        └── [          3]  openresty
            └── [          3]  nginx
                └── [          4]  conf
                    ├── [      10052]  nginx.com.jeremybryansmith.jellyfin.conf
                    └── [      36812]  nginx.com.jeremybryansmith.wiki.conf




For a more formal description of what I want the project TO BE, read the transcript of the conversation I had with ChatGPT about creating such a WAF (with the example being for the Vaultwarden web portal) from this file:  './ChatGPT_Openresty-WAAAPI-Firewall-Vaultwarden.txt'




