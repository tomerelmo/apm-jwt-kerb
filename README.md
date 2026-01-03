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
<image>

### Open the chrome browser and Navigate to "https://app2.kerb-jwt.apm"(You may press F12 to make sure that no 401 which force SPNEGO occurred yet - no policy created yet)
<image>

### Now go back to the BIGIP and Lets configure the Per Session Policy

### Navigate to "Access" --->
![Image](https://iili.io/fjAVbDB.png)

### From the menu choose : profile / policies ---> access profile ( per session pfrofile)
<image>

### Press on Create 

### Fill the name and choose "Profile Type" -"all"
<image>

### Scroll down and add the english to the "accepted language" 
<image>

### Create the policy - make sure the policy appear on the list
<image >

### Now on the Policy list , pay attention to the right side of the screen, there on your policy, you will see "Edit" button, press on it
<image>

### The edit button take us to the policy editor page 
<image>

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
<image>

### Press "save". now lets create the Kerberos block: Now press "+" on the negotiate branch
<image>

### Search on the box "Kerberos Auth" select it and press "add item"
<image >

### config the Kerberos box:
* Choose the AAA server that we create 
* Enable request based auth
* Enable extract group SID 
* Fill the group SID variable  with the following variable : session.kerberos.last.groupsids (This is session variable that APM will keep the information of the SID groups ) - We can use them later but , we will query the names of the groups directly from the AD later
<image>

### Now the policy looks like the below:
<image>

### Please press on the branch "Success" "+" sign and add Ldap query (Remember that we created it earlier ?)
<image>

* Choose the server which we created earlier
* Fill in the search DN with DC=kerb-jwt,DC=apm
* And the search filter to :"(userPrincipalName=%{session.logon.last.username})" - this is tells the APM that the userPrincipalName is located on the session variable :session.logon.last.users
* E
