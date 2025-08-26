# Security-Header-Helper-Utility
A simple bash script with multi-distribution support designed to aid in securing and deploying websites in LAMP stacks utilizing Nginx and/or Apache. This script detects missing headers, outputs headers for adding to NGINX and Apache configuration files with a focus on Content-Security-Policy and CDN JS configs 

## Options
```
-u Checks URL for Content-Security Policy (work in progress)
--url Generates Content-Security-Policy based off existing JavaScript library URL's
-m Generates missing headers excluding Content-Security-Policy
-f injects into a named configuration file (work in progress)
```

# Current Options
![Imgur Image](https://i.imgur.com/WxL4q3C.png)

## --url CSP Header Generator / JS Library Parser Option
![Imgur Image](https://i.imgur.com/sS4dv7m.png)
！ Vulnerabilities are currently not parsed and outputted in this version of the script.

![Imgur Image](https://i.imgur.com/QxiKKqB.png)
## -u Content-Security-Policy Header Check Option
![Imgur Image](https://i.imgur.com/uERXM3g.png)
## -m Make Header Option
![Imgur Image](https://i.imgur.com/dOXnXIU.png)
