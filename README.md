<div align="center">


<h3 align="center">Curi Auth Server</h3>

 
</div>


### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/RIDEAT/curi-auth.git
   ```
2. Move to it
   ```sh
   cd curi-auth
   ```
3. Make jwt-secret in src/main/resources/application-jwt.properties 
   ```sh
   echo 'jwt.authSecretKey = your own secret key' >> application-jwt.properties
   ```
   ```sh
   echo 'jwt.refreshSecretKey = your own secret key' >> application-jwt.properties
   ```
   ```sh
   echo 'jwt.authExpiredMs = your own secret key' >> application-jwt.properties
   ```
   ```sh
   echo 'jwt.refreshExpiredMs = your own secret key' >> application-jwt.properties
   ```
4. Make  src/main/resources/serviceAccountkey.json to connect firebase
   
5. Local Build
   ```sh
   ./gradlew build
   ```
   
6. Docker Build
    
    ```sh
    // For mac
    docker build . -t springbootapp --platform linux/amd64
    ```
    ```sh
    // For window
    docker build . -t springbootapp 
    ```
7. Docker Run
    ```sh
    docker run springbootapp
    ```
Followings are options that you can add! 
* Port option(-p)
  <br>Connect between local network and container inner network.

* Volume option(-v)
<br>Enable inner container to use local files 

### Reference 
[Here](https://ttl-blog.tistory.com/761 ) is the website that I referred to when building 

