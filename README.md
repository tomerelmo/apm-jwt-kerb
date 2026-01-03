## Welcome to Kerberos to JWT lab

### Scenario: Client(win11)  will turn to BIGIP with kerberos, the BIGIP will take the details such as username and group and Generate JWT token to send to the backend.


## You may open to see the flow graph
[Image](https://iili.io/fXSdjG1.png?width=300)


### dsram pass: f5apmtrain

## components 
* 2 X BIGIP - One is for the example and the other is for practice - if you are stuck with the configuration you may take look on the Example BIGIP.
* Windows 11 - this is the client and management desktop - from here we will turn to the URL : <TBD>
* Windows 2019 - 10.1.1.7(Mgmt subnet) -act as AD and DNS server for this lab.
* Ubuntu_1 - This is the backend server which get the JWT for the example machine
* Ubuntu_2 - This is the practice backend server running echo application that return the exact http request its gets.

## Documentation links

* https://my.f5.com/manage/s/article/K000148782 -- Kerberos multiple KBs.



# Kerberos → BIG-IP APM → JWT Low-Level Flow

## Phase 0 — Pre-existing Objects

### Active Directory
- Service account: `svc_bigip@KERB-JWT.APM`
- SPN: `HTTP/app.kerb-jwt.apm` mapped to `svc_bigip`
- Secret key stored in AD
- Keytab: exported secret for BIG-IP

---

## Phase 1 — Client Access
1. User browses: `https://app.kerb-jwt.apm`
2. DNS resolves to BIG-IP VIP

---

## Phase 2 — Kerberos Ticket Request
3. Browser builds SPN: `HTTP/app.kerb-jwt.apm@KERB-JWT.APM`
4. Browser requests service ticket from AD KDC
5. AD returns ticket encrypted with `svc_bigip` secret

---

## Phase 3 — SPNEGO Delivery
6. Browser sends:
```
Authorization: Negotiate <kerberos-ticket>
```

---

## Phase 4 — BIG-IP Decrypts
7. BIG-IP uses `/config/krb5.keytab`
8. Ticket decrypted → user identity extracted

---

## Phase 5 — APM Identity Pipeline
9. Kerberos Auth agent populates session
10. LDAP Query enriches identity attributes

---

## Phase 6 — JWT Creation
11. JWT Provider builds payload
12. BIG-IP signs token (RS256)

---

## Phase 7 — Token Delivery
13. BIG-IP injects JWT to backend:
```
Authorization: Bearer <JWT>
```

---

## Phase 8 — Application Trust
14. App validates JWT signature and claims
.
.



## other details
* The domain is: kerb-jwt.apm
* Domain admin password: F5apmtrain!
* Name: svc_bigip
* UPN: svc_bigip@kerb-jwt.apm
* Password: F5apmtrain!
* BIGIP Password: F5apmtrain!


## Now lets deep dive into configure Kerberos to JWT on app2.kerb-jwt.apm

### Please go to :<the vs locaton> open the vs object <TBD> and scroll down to the APM section, pay attention that there is pes session policy part, this is the part we are going to concentrate, we will build the policy and config on that box.

# step 1 : 
## Lets buckle up and understand what we are doing first.

### On BIPGIP - most of the time we build Virtual Server that will act as a proxy - what let us interfere between the client and the server and change stuff (on our case, authenticate with kerberos on the client side and send JWT on server side.)

### Within this page you may see "Components" - press on it and BIGIP-Practice should appear
![Image](https://iili.io/fjzvNef.png)

### please press on "Access"and then "TMUI"

### The BIGIP welcome screen will appear - Go into "Local Traffic" then to "Virtual Server" then "Virtual Server List"
![Image](https://iili.io/fjz7611.png)

### There you should find the our Echo server 
![Image](https://iili.io/fjz7SzQ.png)

### Press and scroll down to "Access" after we will create the building blocks , the result will end here - we will create policy which we need to choose here.
![Image](https://iili.io/fjz74qP.png)





# Step 2:

### Login to the WinServer by RDP (User: KERB-JWT\Admin | Passwrod: F5apmtrain! )

### Open the DC DNS management system and make sure that we have app2.kerb-jwt.apm with ip address 10.1.20.21 (Our virtual server)
![Image](https://iili.io/fjIIKEg.png)

### Open the DC Active directory users an computer - make sure that you see bigip service account (svc_bigip)
![Image](https://iili.io/fjAzA9j.png)

### Open the Powershell using admin account (Run as administrator)

### Create spn for the second app using the service account :
```text
setspn -S HTTP/app2.kerb-jwt.apm svc_bigip
```
### Query and check that the SPN created 

```text
setspn -Q HTTP/app2.kerb-jwt.apm
```
### Create KTPASS (keytab) that we will upload to BIGIP APM later:
```text
 ktpass -princ HTTP/app2.kerb-jwt.apm@KERB-JWT.APM -mapuser svc_bigip@KERB-JWT.APM -crypto AES256-SHA1 -pass F5apmtrain! -out c:\temp\bigip.keytab
```

-------------------------------------------------------------------------

# Step 3:

### Here we going to create the Authentication-LDAP and Authentication Kerberos object which we will use later to build the Per Session Policy

### Open chrome on the DC server , navigate to the BIGIP 10.1.1.4 (User: admin | Passwrod: F5apmtrain! )
![Image](https://iili.io/fjAVpoP.png)

### After creating the SPN and generating the keytab file, we configure BIG-IP APM to authenticate with Active Directory and decrypt the Kerberos SPNEGO token in order to retrieve the authenticated user identity.

### Now we will create the LDAP object which later we going to use for query the authenticated user attributes 

### Navigate to Access --> 
![Image](https://iili.io/fjAVbDB.png)

### Open the "Authentication" ---> "LDAP"
![Image](https://iili.io/fjAVtAQ.png)

### Press create and fill the object deatails, remember we are using the "admin" user and the password is "F5apmtrain" and of courese the ldap id and the name of the object we will use port 389 for this lab:
![Image](https://iili.io/fjA8UG4.png)

### Press finished to create the object.

### Under access menu press on "Authentication" again but now Navigate to "Kerberos" and to "AAA" server. fill in the following details and 
* name : any ( try to make it informative)
* Auth- realm : KERB-JWT.APM
* Service name : HTTP
* Upload the keytab we created using the KTPASS command ( Located on c:\temp)

<image of the kerberos here >

### Under access menu press on "Authentication" again but now Navigate to "Kerberos" and to "Kerberos Auth configuration". fill in the following details 
* name 
* choose the AAA server which we created 
* Leave the rest as is and press finish
<image>

---------------------------
# Step 4:

### Lets create PerSession Policy and test our objects to have kerberos authentication for entering the application.

### On the LAB page go to components and login with RDP to the "Client Desktop" station (User: f5_student | Passwrod: F5apmtrain! )
![Image]()

### Open the chrome browser and Navigate to "https://app2.kerb-jwt.apm"(You may press F12 to make sure that no 401 which force SPNEGO occurred yet - no policy created yet)
![Image]()

### Now go back to the BIGIP and Lets configure the Per Session Policy

### Navigate to "Access" --->
![Image](https://iili.io/fjAVbDB.png)

### From the menu choose : profile / policies ---> access profile ( per session pfrofile)
![Image]()

### Press on Create 

### Fill the name and choose "Profile Type" -"all"
![Image]()

### Scroll down and add the english to the "accepted language" 
![Image]()

### Create the policy - make sure the policy appear on the list
![Image]()

### Now on the Policy list , pay attention to the right side of the screen, there on your policy, you will see "Edit" button, press on it
![Image]()

### The edit button take us to the policy editor page 
![Image]()

### Between the block of "Start" and the block of "Deny" - there is line with word "Fallback" and "+" sign near to it - press on "+".

### We are going to add blocks to that policy , there blocks are define the flow which the application will go to authenticate 

#### Lets talk aside on the behavior when Domain user authenticate with kerberos on a site 
* Browser send to the BIGIP(APM) Virtual server "GET" request 
* For the browser to trigger ticket from the AD, the browser need to see response code 401
* When browser see that 401, and the Header "WWW-Authenticate: Negotiate" Ask form the OS the cache kerberos ticket (TGT) for the user that own the proccess.
* The browser contacts the KDC (Key Distribution Center) on the DC
* The DC verifies the user is valid and issues a Service Ticket (ST). This ticket is encrypted with the Web Server's secret password. The browser cannot read it; it can only hold it.
* The browser re-send the GET request with Header: Authorization: Negotiate XXX. - the value "XXX" is base 64 encode for the ticket
* Since the BIGIP(APM) have the Keytab from the DC he can decrypt the key and see the user identity .
 
### The explanation above is written in order for you to understand the flow which we are going to create .

### Now from the option that you see , choose "401 Response" and change the "HTTP Auth Level" to "negotiate" - We basically tell the APM to response with 401 and with header negotiate , and browser need to understand it as "i need to provide the TGT"
![Image]()
#### Go to branch rule and make sure these 2 branch rules (Press add branch rules and advance):
#### Press add branch rule , "change" and then "advance" and make sure you see the folloiwng string 
```text
expr {[string tolower [mcget {session.logon.last.authtype}]] == "basic"} 
```
####  "change" and then "advance" on the second rule make sure you see the folloiwng string 
```text
expr {[string tolower [mcget {session.logon.last.authtype}]] == "negotiate"}
```
 #### The rule define if this block is seccessful, the browser need to reply with either negotiate or basic authtype to be count as successful.
![Image]()

### Press "save". now lets create the Kerberos block: Now press "+" on the negotiate branch
![Image]()

### Search on the box "Kerberos Auth" select it and press "add item"
![Image]()

### config the Kerberos box:
* Choose the AAA server that we create 
* Enable request based auth
* Enable extract group SID 
* Fill the group SID variable  with the following variable : session.kerberos.last.groupsids (This is session variable that APM will keep the information of the SID groups ) - We can use them later but , we will query the names of the groups directly from the AD later
![Image]()

### Now the policy looks like the below:
![Image]()

### Please press on the branch "Success" "+" sign and add Ldap query (Remember that we created it earlier ?)
![Image]()

* Choose the server which we created earlier
* Fill in the search DN with DC=kerb-jwt,DC=apm
* And the search filter to :"(userPrincipalName=%{session.logon.last.username})" - this is tells the APM that the userPrincipalName is located on the session variable :session.logon.last.users
* Enable also "Fetach groups..." and Save 
![Image]()

### Change the "Group Membership" brach to "Allow"
![Image]()

### Do the same for the fallback branch under the LDAP query
![Image]()

### UP on the right screen there is message "Apply Access Policy" - press on it for the policy to be saved and ready.

### Now lets go back to "Local Traffic" module ---> Virtual server ---> Virtual server list
![Image]()

### Press on out virtual server and scroll down to Acess section , we will choose our policy and them on update.
![Image]()

### Preconfigured this lab i have added the site to the chrome and edge authenticaton :
```text
reg add "HKLM\Software\Policies\Microsoft\Edge" /v AuthServerAllowlist /t REG_SZ /d app2.kerb-jwt.apm /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v AuthNegotiateDelegateAllowlist /t REG_SZ /d app2.kerb-jwt.apm /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v EnableAuthNegotiatePort /t REG_SZ /d 443 /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v DisableAuthNegotiateCnameLookup /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v AuthServerAllowlist /t REG_SZ /d app2.kerb-jwt.apm /f
reg add "HKLM\Software\Policies\Google\Chrome" /v AuthNegotiateDelegateAllowlist /t REG_SZ /d app2.kerb-jwt.apm /f
reg add "HKLM\Software\Policies\Google\Chrome" /v EnableAuthNegotiatePort /t REG_SZ /d 443 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v DisableAuthNegotiateCnameLookup /t REG_DWORD /d 1 /f
```

### Now lets test the policy :
* Under the Components section of the lab page, head to BIGIP practice and open the WEB Shell .
* On the webshell tail the APM logs , for watching what is going on during our authentication phase.
* Enter the command : ```bash tail -f /var/log/apm```
![Image]()
* * Login to the client windows11 - User: f5_student Pass: F5apmtrain!
* Open the Internet Option from the windows, and make sure our FQDN listed on the Local Inranet sites (Sites and then advance) list under security section.
![Image]()
* Afthe verification, open the edge browser and before entering the FQDN open the Dev tools 
* enter the FQDN : app2.kerb-jwt.apm 
* If the authenticaton is failed - what may be wrong ? time synchronazation ?
* Upon success watch the apm send 401 to the browser with WWW negotiate Header
* Browser sending ""authorization": "Negotiate....." with the ticker as base64 code, if you got this -- that the end of this step (not so long ah ?)
* Of course you can now view the application 
![Image]()

### Pro TIP : tail the logs that we showed earlier for understand or solve an issue, upon hard issue, we may activate debug logs (for another session :))

## Step 5:
### Now lets create the building blocks for the JWT sending 
### As you noticed we have added "LDAP Query" block to our policy, this was for getting the groups that belongs to the user and put them on the JWT claims

### We will create the following blocks
* JSON web toekn key configuration
* Token configuration
* Oauth cliams
* Oauth Bearer - here we are adding the key configuration and the Oauth claims
* Then we are adding the oauth bearer object to the "per session policy" we created to generate the JWT

### First building block : JSON web toekn key configuration 
### under Access go to "Federation" ---> "Json Web Token" ---> "Key configuration" - create
* Fill the name 
* Fill the ID - importnant
* JWT type - JWS
* Type RSA
* signin Algorithim : RS256
* certificate file, key and chain : choose default -- While the server you send will validate the jwt, he needs to have the certificate (not the p.key) on the server 
![Image]()

### under Access go to "Federation" ---> "Json Web Token" ---> "Token configuration" - create
* name : choose name
* issuer : https://bigip.kerb-jwt.apm 
* Audience : add "app2"
* Allowed singin algorithm: RS256
* Allowed keys : the key we created above
![Image]()

### under Access go to "Federation" ---> "Oauth Authorization server" ---> "claims" - create
* Name: object name choose one 
* type : leave string
* Claim name: groups 
* Claim value : %{session.ldap.last.attr.memberOf} --- we are taking the groups from the APM session and putting it on the claims of the JWT
* Repeat the proccess for UPN and 
```text
upn | %{session.ldap.last.attr.userPrincipalName}
user_id | %{session.logon.last.username}
```
![Image]()

### under Access go to "single sign on" ---> OAuth Bearer - create
* choose a name 
* send token : always - on production system consider if to choose 4XX response according to your authentication style
* Token source : Generate toekn
* Issuer : http://bigip.kerb-jwt.apm
* JWT key Type : JWS
* JWT primary key : choose the key configuration we created earlier
* Audienc : app2
* JWT Claims: move the 3 we created to selected 
![Image]()
### under Access go to "Profile/ policies" ---> "Access Profiles (Per-Session Policies)" - press on your policy object name
* under SSO/Auth Domains select our SSO configuration

### Now go back to the client station and once again, try to reach the server , watch the token 
![Image]()
# The end


