- Instructions to setup Node Server for Evilginx Logs..

- REQUIREMENTS:
 1) nodejs (above v14.15.4)
 2) npm (above v6.14.10)
 Refer to this blog to know how to install these versions ( https://www.freecodecamp.org/news/how-to-install-node-js-on-ubuntu-and-update-npm-to-the-latest-version/)
 
- STEPS:
 1) Copy All files inside the VPS server.(USE ONLINE FILE SHARING ANG wget or USE FTP)
 2) Unzip the zipped File 
	'cd ~/.evilginx/ && unzip Web-Panel-Evilginx.rar '
 3) Create a Symblink of data.db file of evilginx logs inside the web panel files
   'ln -s ~/.evilginx/data.db ~/.evilginx/Web-Panel-Evilginx/data.db'
 4) Go to the extracted web panel files and install required packages.
   'npm install package.json'
   
 5) Run the Server using ' node app.js ' 
    // You should run it inside the screen in vps 
	 use ' screen '
	 to get a new terminal 

 6) Server will Run on port 3000
    Browse it using  182.xxxx.xx:3000 
    where the 182.xxx.xxx is your server IP address.	

https://t.me/newtonpmta0
https://t.me/newtonpmta