# Security-Header-Helper-Utility
A simple bash script with multi-distribution support designed to aid in securing and deploying websites in LAMP stacks utilizing Nginx and/or Apache. This script detects missing headers, outputs headers for adding to NGINX and Apache configuration files with a focus on Content-Security-Policy and CDN JS configs 

## Options
```
-u Checks URL for Content-Security Policy (work in progress)
--url Generates Content-Security-Policy based off existing JavaScript library URL's
-m Generates missing headers excluding Content-Security-Policy
-f injects into a named configuration file (work in progress)
```

