# Smart Alarm
## File Structure

    |-site
        |-js
            |-custom.js
        |-css
            |-login.css
            |-panel.css
        |-index.html
        |-panel.html
    |-xml
        |-response.xml
    |-package.json
    |-server.js
        
#### Site Folder
Contains the web application's source codes
#### Xml Folder
Contains the response text
#### package.json
Node module dependencies
#### server.js
NodeJS server

## Installation
1. Install nodejs
    - Windows/Mac - https://nodejs.org/en/download/
    - Linux - https://www.ostechnix.com/install-node-js-linux/
2. Clone repo

       git clone https://github.com/ajimal1992/smart-alarm.git
3. Go to repo directory

       cd smart-alarm
4. Install dependencies

       npm install
5. Start server

       node server.js
6. Browse to - https://localhost:55555/login


##### Note
Please remember to add the the dependency module to package.json if you have installed any. You can do so by

    npm install <some-package> --save
