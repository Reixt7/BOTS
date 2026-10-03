# Сценарий 1

101. What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

Так как атака велась на домен `imreallynotbatman.com`, вбиваю его в поиск:

```
index=botsv1 imreallynotbatman.com
```

![[Pasted image 20260928120544.png]]

**Ответ:** `40.80.148.42`

---

102. What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.

Сканирование на веб-ресурс сопровождается огромным количеством за короткий промежуток времени методом POST. Следовательно я вбиваю в поиск

```
index="botsv1" imreallynotbatman.com src="40.80.148.42" http_method=POST
```

![[Pasted image 20260928121000.png]]

**Ответ:** `Acunetix`

---

103. What content management system is imreallynotbatman.com likely using?

Оставив тот же самый запрос видно, какой CMS использует веб-ресурс

![[Pasted image 20260928122155.png]]

**Ответ:** `Joomla`

---

104. What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?

Хакер возможно сменил свой IP-адрес после разведки, поэтому было решено написать запрос 

```
index=botsv1 sourcetype=stream:http src_ip=192.168.250.70
```

Таким образом я увижу кому и какой именно контент отдавал веб-сервер

![[Pasted image 20260928155949.png]]

**Ответ:** `poisonivy-is-coming-for-you-batman.jpeg`

---

105. This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

При исследовании события со скачиванием defac файла `poisonivy-is-coming-for-you-batman.jpeg` в том же самом HTTP-логе проверяем HTTP-заголовки запроса (`Host` / поле `site`):

![[Pasted image 20260928160541.png]]

**Ответ:** `prankglassinebracket.jumpingcrab.com`

---

106. What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

В этом же событии хранится IPv4:

![[Pasted image 20260928160840.png]]

**Ответ:** `23.22.63.114`

---

108. What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

Попытка брутфорса = перебор логина с паролем, значит вписываю такой запрос:

```
index=botsv1 dest_ip=192.168.250.70 sourcetype="stream:http" http_method=POST form_data="*username*" form_data="*passwd*"
```

![[Pasted image 20260928163601.png]]

**Ответ:** `23.22.63.114`

---

109. What is the name of the executable uploaded by Po1s0n1vy?

Найти исполняемый файл (.exe) значит пишу dest IP веб-сайта и .exe

```
index=botsv1 dest_ip="192.168.250.70" http_method=POST .exe
```

![[Pasted image 20260928170507.png]]

Какой конкретно из этих двоих файлов нужен, не известно, провожу расследование глубже по `3791.exe`:

```
index=botsv1 3791.exe
```

Проверяю `sourcetype`

![[Pasted image 20260928171740.png]]

и видно, как больше кол-во записей записано в Sysmon, по нему и ищу ивенты связанные с файлом:

```
index="botsv1" 3791.exe sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
```

Результат:
```
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2016-08-10T22:08:13.902098100Z'/><EventRecordID>443590</EventRecordID><Correlation/><Execution ProcessID='1296' ThreadID='1416'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>we1149srv.waynecorpinc.local</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='UtcTime'>2016-08-10 22:08:13.902</Data><Data Name='ProcessGuid'>{E500B0EA-A5CD-57AB-0000-0010F530DD01}</Data><Data Name='ProcessId'>3424</Data><Data Name='Image'>C:\Windows\SysWOW64\cmd.exe</Data><Data Name='CommandLine'>C:\Windows\system32\cmd.exe</Data><Data Name='CurrentDirectory'>C:\inetpub\wwwroot\joomla\</Data><Data Name='User'>NT AUTHORITY\IUSR</Data><Data Name='LogonGuid'>{E500B0EA-219E-57AA-0000-0020E3030000}</Data><Data Name='LogonId'>0x3e3</Data><Data Name='TerminalSessionId'>0</Data><Data Name='IntegrityLevel'>High</Data><Data Name='Hashes'>SHA1=F5CFD4070EA7D2B40A29F21F9E29AF23341C59EC,MD5=59A1D4FACD7B333F76C4142CD42D3ABA,SHA256=E1A080E61FB1BAF0DA629D34BAEE6F0F9D0E0337BF6CED9F4B3AB9B1C23D91BA,IMPHASH=5B13496CE269DF7709AAB6B1BBF99CD3</Data><Data Name='ParentProcessGuid'>{E500B0EA-A302-57AB-0000-00108D65C301}</Data><Data Name='ParentProcessId'>3880</Data><Data Name='ParentImage'>C:\inetpub\wwwroot\joomla\3791.exe</Data><Data Name='ParentCommandLine'>3791.exe  </Data></EventData></Event>
    host = we1149srv
    source = WinEventLog:Microsoft-Windows-Sysmon/Operational
    sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

```

```xml
<Data Name='ParentImage'>C:\inetpub\wwwroot\joomla\3791.exe</Data> 
<Data Name='ParentCommandLine'>3791.exe </Data>
```

Вредоносный файл `3791.exe` лежит прямо в веб-директории CMS (`C:\inetpub\wwwroot\joomla\`). Нормальные исполняемые файлы ОС там не находятся.

```
<Data Name='Image'>C:\Windows\SysWOW64\cmd.exe</Data> 
<Data Name='User'>NT AUTHORITY\IUSR</Data>
```

`3791.exe` создаёт командную строку

```
<Data Name='IntegrityLevel'>High</Data>
```

Уровень привbлегий High, что указывает на высокую степень угрозы.

**Ответ:** `3791.exe`

---

110. What is the MD5 hash of the executable uploaded?

**Ответ:** `MD5=59A1D4FACD7B333F76C4142CD42D3ABA`

---

111. GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

Здесь нужно провести расследование в интернете проверив в VirusTotal IP-адрес `23.22.63.114` 

![[Pasted image 20261003140211.png]]

**Ответ:** `9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8`

---

112. What special hex code is associated with the customized malware discussed in question 111?

В вкладке **Community** есть ответ

![[Pasted image 20261003140406.png]]

**Ответ:** `4e 65 6c 20 6d 65 7a 7a 6f 20 64 65 6c 20 63 61 6d 6d 69 6e 6f 20 64 69 20 6e 6f 73 74 72 61 20 76 69 74 61 20 6d 69 20 72 69 74 72 6f 76 61 69 20 70 65 72 20 75 6e 61 20 73 65 6c 76 61 20 6f 73 63 75 72 61`

---

114. What was the first brute force password used?

```
index=botsv1 dest_ip="192.168.250.70" sourcetype="stream:http" http_method=POST form_data="*username*passwd*"
| rex field=form_data "passwd=(?<password>[^&]+)"
| sort 0 _time
| head 1
| table _time, src_ip, dest_ip, password
```

**Ответ:** `12345678`

---

115. One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?
```
index=botsv1 sourcetype=stream:http dest=192.168.250.70 http_method=POST form_data="*username*passwd*"
| rex field=form_data "passwd=(?<userpassword>[^&]+)"
| eval lenpword=len(userpassword)
| search lenpword=6
| eval password=lower(userpassword)
| lookup coldplay.csv song as password OUTPUTNEW song
| search song=*
| table song password
```

![[Pasted image 20261003142523.png]]

**Ответ:** `yellow`

---

116. What was the correct password for admin access to the content management system running "imreallynotbatman.com"?

```
index=botsv1 sourcetype="stream:http" http_method=POST form_data="*username*passwd*"
|rex field=form_data "passwd=(?<Password>\w+)"
|stats count values(src) by Password
|sort — count
```

![[Pasted image 20261003144518.png]]

**Ответ:** `batman`

---

117. What was the average password length used in the password brute forcing attempt?

```
index=botsv1 sourcetype=stream:http
|rex field=form_data "passwd=(?<Password>\w+)"
|search Password=batman
|transaction Password
|table duration
```

![[Pasted image 20261003144651.png]]

**Ответ:** `92.17`

---

118. How many unique passwords were attempted in the brute force attempt?

```
index=botsv1 sourcetype=stream:http form_data=*username*passwd*
|rex field=form_data "passwd=(?<Password>\w+)"
|stats dc(Password)
```

![[Pasted image 20261003144847.png]]

**Ответ:** `412`