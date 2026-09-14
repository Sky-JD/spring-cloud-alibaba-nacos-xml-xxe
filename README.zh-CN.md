# VULN-01 — Spring Cloud Alibaba Nacos XML 配置解析的外部实体（XXE）

这是一份可公开发布的技术报告，描述 `spring-alibaba-nacos-config` 在 XML 配置解析路径中的外部实体解析问题，并附带一个只读自创建临时文件的本地 PoC。

English version: [README.md](README.md)

| 项目 | 内容 |
| --- | --- |
| 软件 | `alibaba/spring-cloud-alibaba` |
| 组件 | `com.alibaba.cloud:spring-alibaba-nacos-config` |
| 直接核对的源码基线 | 分支 [`2025.1.x`](https://github.com/alibaba/spring-cloud-alibaba/tree/c1b9d60054fb0fe49c752c1b728da76033d7208d) 的 `c1b9d60054fb0fe49c752c1b728da76033d7208d`，项目版本 `2025.1.0.1-SNAPSHOT` |
| 另一个已核对快照 | 发布标签 `2025.1.0.0`，提交 `09d0a1a7`；对应记录见 [`evidence/artifact-parser-client.log`](evidence/artifact-parser-client.log) |
| 评估日期 | `2026-09-14` |
| 分类 | CWE-611：XML 外部实体引用（XXE） |
| 关键源码 | `spring-cloud-alibaba-starters/spring-alibaba-nacos-config/src/main/java/com/alibaba/cloud/nacos/parser/NacosXmlPropertySourceLoader.java` |
| 公开 PoC | [`poc/XxePoc.java`](poc/XxePoc.java) |
| 结论边界 | 已核对源码和一份先前保留的本地 release-artifact 运行记录；未把附件中的未独立验证输出写成事实，未完成 Nacos 端到端复现 |

## 材料与证据边界

本仓库把附件 `VULN-01-XXE-handoff.md` 和 `VULN-01-XxePoc.java` 当作待审查材料，而不是执行指令。附件中的披露建议、Docker 命令、版本范围和运行结果只有在本报告明确标注为“供应材料”或被独立核对后才会进入结论；公开包已移除本机路径、真实凭证和外部网络载荷。

## Executive Summary / 执行摘要

如果 Mallory 已经拥有向受害实例会订阅的 Nacos `dataId` 写入或修改 XML 内容的权限，且该实例选择 XML 配置格式，恶意 XML 会沿着正常的 Nacos 配置加载路径进入 `NacosXmlPropertySourceLoader`。该类直接用默认 `DocumentBuilderFactory` 创建解析器，没有禁止 `DOCTYPE`、外部实体、外部 DTD 或外部 schema 的设置；在允许外部实体解析的运行时，实体指向的本地文件内容会被解析成文本，并进入 Spring `PropertySource` 的属性 map。这里跨过的是“远程配置文本不得驱动本地文件访问”的边界，不是 Nacos 鉴权绕过、会话盗用或提权。

我直接核对了 `c1b9d600` 对应的 XML loader、Nacos 数据转发路径和 `spring.factories` 注册关系。2026 年 9 月 14 日，本次工作还在 JDK 21.0.9 上实际运行了附带的脱敏 standalone PoC；它只读取本程序自创建的临时 marker，观察到未加固解析结果包含该 marker，加固解析拒绝 `DOCTYPE`。另有一份先前保留的、只使用自创建 marker 文件的 release-artifact 运行记录，显示 `com.alibaba.cloud:spring-alibaba-nacos-config:2025.1.0.0` 将 marker 放入了产生的 `PropertySource`。附件声称的 standalone 输出不作为独立证据；本报告使用的是上述可复核的当前 PoC 观察和单独标明的历史记录。

本稿只确认上述源码基线以及该份 release-artifact 记录，不据此给出首个受影响版本、完整受影响范围、首个修复版本、CVE、CVSS 或官方修复状态结论。Nacos 权限配置、应用是否有回显/外泄通道，以及 Spring Boot 外层是否在特定组合中拦截 `DOCTYPE`，也未在本稿中完成端到端核验。

## Background / 背景

### 完整的受控数据流

1. 受害应用引入 `spring-alibaba-nacos-config`，由 Nacos 客户端获取某个 `dataId` 的配置字符串。
2. 在 `NacosPropertySourceBuilder.loadNacosData` 中，配置服务返回的 `data` 被传给 `NacosDataParserHandler.parseNacosData`。Config Data 路径在 `NacosConfigDataLoader.pullConfig` 中也执行同样的转发。
3. `NacosDataParserHandler` 根据扩展名挑选 `PropertySourceLoader`，将原始字符串包装为 `NacosByteArrayResource`，随后调用 loader 的 `load` 方法。
4. `spring.factories` 注册 `NacosXmlPropertySourceLoader`，该 loader 声明支持 `xml`；它把 XML 解析为 map，再返回 `OriginTrackedMapPropertySource`。

`NacosPropertySourceBuilder` 在审计版本中的关键路径如下（源码路径：`spring-cloud-alibaba-starters/spring-alibaba-nacos-config/src/main/java/com/alibaba/cloud/nacos/client/NacosPropertySourceBuilder.java`，约第 96–122 行）：

```java
String data = null;
String configSnapshot = NacosSnapshotConfigManager
        .getAndRemoveConfigSnapshot(namespace, dataId, group);
if (configSnapshot == null) {
    data = configService.getConfig(dataId, group, timeout);
}
// ...
return NacosDataParserHandler.getInstance().parseNacosData(dataId, data,
        fileExtension);
```

`NacosDataParserHandler.parseNacosData` 的相关逻辑（源码路径：`spring-cloud-alibaba-starters/spring-alibaba-nacos-config/src/main/java/com/alibaba/cloud/nacos/parser/NacosDataParserHandler.java`，约第 68–95 行）保持原始文本，并把它交给匹配的 loader：

```java
if (!StringUtils.hasLength(extension)) {
    extension = this.getFileExtension(configName);
}
for (PropertySourceLoader propertySourceLoader : Objects.requireNonNull(propertySourceLoaders)) {
    if (!canLoadFileExtension(propertySourceLoader, extension)) {
        continue;
    }
    NacosByteArrayResource nacosByteArrayResource;
    if (propertySourceLoader instanceof PropertiesPropertySourceLoader) {
        nacosByteArrayResource = new NacosByteArrayResource(
                NacosConfigUtils.selectiveConvertUnicode(configValue).getBytes(),
                configName);
    }
    else {
        nacosByteArrayResource = new NacosByteArrayResource(
                configValue.getBytes(), configName);
    }
    nacosByteArrayResource.setFilename(getFileName(configName, extension));
    List<PropertySource<?>> propertySourceList = propertySourceLoader
            .load(configName, nacosByteArrayResource);
}
```

审计版本的默认扩展名常量为 `properties`；XML 是被选择的配置格式，而不是默认格式。典型触发选择是 `spring.cloud.nacos.config.file-extension=xml`，或者从 `dataId` 推导出 XML 扩展名。`canLoadFileExtension` 使用大小写不敏感的 `endsWith` 匹配，因此扩展字符串以 `xml` 结尾时也会进入该 loader；这只扩大可达性，不改变漏洞根因。

注册关系来自同一版本的 `spring-cloud-alibaba-starters/spring-alibaba-nacos-config/src/main/resources/META-INF/spring.factories`：

```properties
org.springframework.boot.env.PropertySourceLoader=\
com.alibaba.cloud.nacos.parser.NacosJsonPropertySourceLoader,\
com.alibaba.cloud.nacos.parser.NacosXmlPropertySourceLoader
```

`NacosXmlPropertySourceLoader.getOrder()` 返回 `Integer.MIN_VALUE`，使它具有最高的 loader 优先级。正常的安全行为应当是：XML 可以表达普通配置节点，但外部实体解析、外部 DTD、XInclude 和外部 schema 访问必须被禁止，或者在不支持安全设置时直接失败。

## Vulnerability Details / 漏洞详情

### 1. Mallory 控制的输入

Mallory 不需要伪造 XML 文件路径，也不需要读取受害主机上的文件。她只需把下列形态的 XML 文本写入一个受害应用会加载的 XML `dataId`；报告附带的 PoC 会先创建自己的临时 fixture，再用 `Path.toUri()` 生成实体 URI：

```xml
<?xml version="1.0"?>
<!DOCTYPE config [
  <!ENTITY localMarker SYSTEM "file://<本次运行创建的临时 fixture>">
]>
<config><leaked>&localMarker;</leaked></config>
```

这个载荷的安全测试对象是 PoC 自己创建的 marker，不是系统密码、云元数据、其他用户文件或外部 URL。

### 2. 解析器缺少安全边界

源码路径：`spring-cloud-alibaba-starters/spring-alibaba-nacos-config/src/main/java/com/alibaba/cloud/nacos/parser/NacosXmlPropertySourceLoader.java`，审计版本约第 101–115 行：

```java
private @Nullable Map<String, Object> parseXml2Map(Resource resource) throws IOException {
    Map<String, Object> map = new LinkedHashMap<>(32);
    try {
        DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance()
                .newDocumentBuilder();
        Document document = documentBuilder.parse(resource.getInputStream());
        if (null == document) {
            return null;
        }
        parseNodeList(document.getChildNodes(), map, "");
    }
    catch (Exception e) {
        throw new IOException("The xml content parse error.", e.getCause());
    }
    return map;
}
```

这段代码在 `newDocumentBuilder()` 前没有设置 `XMLConstants.FEATURE_SECURE_PROCESSING`、`disallow-doctype-decl`、外部通用实体/参数实体开关、`ACCESS_EXTERNAL_DTD`、`ACCESS_EXTERNAL_SCHEMA`、XInclude 或实体解析器。源码本身因此没有建立“外部实体不可访问”的保证；具体是否实际解析外部实体仍取决于运行时 XML parser 的默认行为。

### 3. 外部实体内容如何成为配置值

同文件约第 118–145 行的 `parseNodeList` 将叶子节点的文本放入 map：

```java
if (node.getNodeType() == Node.ELEMENT_NODE && node.hasChildNodes()) {
    parseNodeList(node.getChildNodes(), map, key);
    continue;
}
if (value.length() < 1) {
    continue;
}
map.put(parentKey, value);
```

对于 `<config><leaked>&localMarker;</leaked></config>`，DOM parser 若展开实体，`&localMarker;` 的内容会成为文本节点，随后以 `config.leaked` 为 key 写入 map。`doLoad` 再把这个 map 包装为 `OriginTrackedMapPropertySource`。因此，已证明的最窄影响是：攻击者控制的 XML 可以使本地文件内容进入受害进程的配置属性源。是否会被日志、管理端点或业务逻辑进一步返回给 Mallory，取决于具体应用；本报告不把这种后续通道当作已证明事实。

### 4. 供应的 release-artifact 运行记录

先前保留的本地验证使用 `com.alibaba.cloud:spring-alibaba-nacos-config:2025.1.0.0` release artifact、同一运行创建的 marker 文件，并直接调用该 artifact 的 parser contract。记录内容如下（另存于 [`evidence/artifact-parser-client.log`](evidence/artifact-parser-client.log)）：

```text
ARTIFACT_PARSER_MARKER=LOCAL_XXE_MARKER_20260908_7F4FEC5C
ARTIFACT_PARSER_RESULT=LOCAL_XXE_MARKER_REACHED_PROPERTY_SOURCE
```

这份记录支持“该 release artifact 在其验证运行中解析了自创建外部实体，并把 marker 交给了 `PropertySource`”这一具体事实；它不证明 Nacos 传输、写权限、生产部署普遍性或远程回显。它也不是本次起草会话重新观察到的终端输出。

### 5. 版本与修复状态边界

本稿直接核对的是 `2025.1.0.1-SNAPSHOT` 基线 `c1b9d600`，并参考一份 `2025.1.0.0` release-artifact 记录。没有完成所有历史 tag、维护分支、发行补丁和官方修复提交的完整交叉核验，因此不声明“全部活跃分支受影响”、不声明自某个日期起首次引入、也不声明某个版本已经修复。附件中关于完整分支范围、CVSS、CVE 和“官方从未修复”的表述均不作为本稿的已验证结论。

## Exploitability Analysis / 可利用性分析

### 已确认的最窄前提

- 受害应用必须使用包含 `NacosXmlPropertySourceLoader` 的 Nacos 配置 starter。
- 被加载的配置必须选择 XML 解析路径；审计版本默认扩展名为 `properties`，XML 属于显式选择或由 dataId 扩展名推导的路径。
- Mallory 必须能够创建或修改受害实例会读取的 `dataId`，或者控制等价的配置内容来源。源码没有显示出在 parser 这一层进行 Nacos 所有权或写权限校验；这不等于存在 Nacos 鉴权绕过。
- 受害进程的操作系统账户必须能够读取 Mallory 指定的目标文件。PoC 只使用该进程同一程序创建的临时文件。

在这些前提成立时，漏洞原语是“外部实体文件读取并进入本地属性 map”。它不自动授予 root、管理员或 Nacos 管理权限，也不自动形成远程代码执行。若应用没有任何将属性值回显、写入日志或用于敏感操作的后续通道，远程攻击者是否能直接看到文件内容仍需单独验证。

### 未验证的更强路径

本稿没有执行网络 URI、云元数据、外带 DTD、参数实体外带或实体展开压力测试，也没有提供这些操作步骤。SSRF、盲打外带和 DoS 只能作为取决于具体 JAXP 实现、网络策略和资源限制的条件性风险，不在已证明影响中。Spring Boot 外层是否在某些版本组合中预先拒绝 `DOCTYPE`，也没有通过 Nacos 端到端环境排除。

### 控制与证据状态

- **已核对**：源码中的 Nacos 配置获取、loader 选择、`spring.factories` 注册、裸 `DocumentBuilderFactory` 调用和 map 写入路径。
- **供应的可复核记录**：release `2025.1.0.0` artifact 将同一运行创建的 marker 放入 `PropertySource`，见 `evidence/artifact-parser-client.log`。
- **本会话实际执行**：脱敏 `poc/XxePoc.java` 在 JDK 21.0.9 上只读自创建临时 marker，观察到未加固 parser 将 marker 放入 `config.leaked`，加固 parser 拒绝 `DOCTYPE`。
- **运行记录**：稳定标准输出保存在 [`evidence/local-poc-run-20260914.txt`](evidence/local-poc-run-20260914.txt)。
- **仍未完成**：Nacos server + 受害应用完整 bootstrap、不同 JDK/分支矩阵、权限模型和远程回显控制。
- **未声称**：已有 CVE/CVSS、确定的完整受影响范围、固定版本、root/RCE、生产可利用率或上游官方确认。

## Proof of Concept / 复现证明

### PoC 设计与安全边界

[`poc/XxePoc.java`](poc/XxePoc.java) 是一个独立、无第三方依赖的 Java 程序：

1. 创建一个临时目录和其中的 `secret.txt`，内容固定为 `CONTROLLED-LOCAL-SECRET`。
2. 只把这个刚刚创建的文件 URI 写入 XML `DOCTYPE` 外部实体。
3. 用审计源码等价的未加固 parser 解析一次，并打印 `config.leaked`。
4. 用建议的加固 parser 解析同一个字节数组，并打印拒绝结果。
5. 在 `finally` 中删除自己创建的文件和目录。

程序不会连接 Nacos、HTTP、LDAP、云元数据地址或任何外部目标，也不会打开已有的本地文件。它展示的是 parser sink 和 map sink，不是 Nacos 权限绕过或远程数据外带。

### 运行命令

从报告根目录执行：

```sh
cd poc
javac XxePoc.java
java XxePoc
```

PowerShell 等价命令：

```powershell
Set-Location poc
javac .\XxePoc.java
java XxePoc
```

### 预期结果与证据区分

在默认 XML parser 允许外部实体解析的运行时，预期会看到类似：

```text
fixture=created-by-this-process
unhardened.config.leaked=CONTROLLED-LOCAL-SECRET
hardened=rejected (IOException)
```

2026 年 9 月 14 日，本次工作在 JDK 21.0.9 上实际运行了该文件，稳定标准输出为：

```text
fixture=created-by-this-process
unhardened.config.leaked=CONTROLLED-LOCAL-SECRET
hardened=rejected (IOException)
```

这三行只证明本地自创建 fixture 在未加固 parser 中进入了 map，并被建议的加固 parser 拒绝；JAXP 的诊断 stderr 未纳入报告，因为它可能受终端编码影响。若其他运行时对未加固 parser 也输出 `unhardened=rejected (...)`，只能说明该运行时的默认行为阻断了这个载荷，不能把它提升为所有 JDK、所有 parser 实现或 Nacos 端到端均安全的结论。

附件声称的 standalone JDK 21 输出仍不作为独立证据。与之不同，上文列出的 release-artifact marker 记录是先前保留、可复核的运行证据；报告保留其原始两行，并明确它不是当前 PoC 的输出。

### Nacos 端到端复现状态

完整的 Nacos transport/bootstrap 流程需要一个严格隔离的、只绑定 loopback 的 disposable Nacos 环境，以及一个配置为 XML 的受害应用。本次工作没有完成这一端到端流程，因而没有伪造 Nacos 发布命令、响应、日志或 actuator 回显。公开 PoC 有意停留在 release parser contract 和安全本地 fixture，读者若要继续验证，应在无非回环网络接口的隔离环境中使用同样的 marker-only 输入，并单独记录 Nacos 权限与回显条件。

## Remediation / 修复建议

### 建议的源兼容修复

在 `NacosXmlPropertySourceLoader` 中集中创建加固的 `DocumentBuilder`，对安全关键设置采取 fail-closed 策略；不要在 feature 不支持时静默降级为默认解析：

```java
private static final String DISALLOW_DOCTYPE_DECL =
        "http://apache.org/xml/features/disallow-doctype-decl";
private static final String EXTERNAL_GENERAL_ENTITIES =
        "http://xml.org/sax/features/external-general-entities";
private static final String EXTERNAL_PARAMETER_ENTITIES =
        "http://xml.org/sax/features/external-parameter-entities";
private static final String LOAD_EXTERNAL_DTD =
        "http://apache.org/xml/features/nonvalidating/load-external-dtd";

private static DocumentBuilder createHardenedDocumentBuilder()
        throws ParserConfigurationException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature(DISALLOW_DOCTYPE_DECL, true);
    factory.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
    factory.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
    factory.setFeature(LOAD_EXTERNAL_DTD, false);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    factory.setNamespaceAware(false);
    factory.setValidating(false);

    DocumentBuilder builder = factory.newDocumentBuilder();
    builder.setEntityResolver((publicId, systemId) -> {
        throw new SAXException("External entity resolution is disabled");
    });
    return builder;
}
```

将 `parseXml2Map` 中的 `DocumentBuilderFactory.newInstance().newDocumentBuilder()` 替换为 `createHardenedDocumentBuilder()`，并把异常包装从 `e.getCause()` 改为 `e`，保留真正的解析失败原因：

```java
try {
    Document document = createHardenedDocumentBuilder()
            .parse(resource.getInputStream());
    if (document == null) {
        return null;
    }
    parseNodeList(document.getChildNodes(), map, "");
}
catch (Exception e) {
    throw new IOException("The xml content parse error.", e);
}
```

这是一份**建议补丁**，不是已由上游发布或确认的修复。启用 `DISALLOW_DOCTYPE_DECL` 后，含 `DOCTYPE` 的 XML 将被拒绝；根据该类现有注释，XML loader 的目的在于绕过 Spring 默认 loader 的严格处理以支持配置定制，并没有证据表明业务配置需要 DTD。若产品确实必须兼容无外部实体的内部 DTD，应在独立测试后再调整策略，不能直接恢复默认外部访问。

### 回归测试

至少应在 `NacosXmlPropertySourceLoader` 的真实 `load` 入口覆盖：

- 普通 XML 仍能加载，并验证节点值和属性值映射到预期 key。
- 含 `DOCTYPE` 和本地 marker 外部实体的输入抛出 `IOException`，根因保留为 SAX 解析异常。
- 含 XInclude 的输入不会把自创建 fixture 内容导入属性 map。
- 不同 XML 扩展名大小写和普通 dataId 的选择行为不被意外改变。
- 解析器不支持关键安全 feature 或 `ACCESS_EXTERNAL_*` 属性时直接失败，而不是回退到不安全默认值。

应在隔离环境中补充 Nacos 端到端测试，确认配置拉取、刷新和错误处理行为；该测试不应读取宿主机既有秘密，也不应访问任何非回环地址。本稿没有把这些建议测试冒充为已通过的测试。

## Summary / 总结

在已核对的 `2025.1.0.1-SNAPSHOT` 源码基线 `c1b9d600` 中，XML Nacos 配置由 `NacosDataParserHandler` 送入 `NacosXmlPropertySourceLoader`，后者使用未加固的默认 DOM builder，并把解析后的叶子文本写入 `PropertySource`。在 Mallory 能控制受害实例所读取的 XML `dataId`、且运行时允许外部实体解析时，本地文件内容可以进入受害进程的配置属性源；这是本稿能够支持的最窄影响。

先前保留的 `2025.1.0.0` release-artifact marker 记录支持这条 parser-to-`PropertySource` 路径，但没有证明 Nacos 鉴权、生产配置、远程回显、SSRF、DoS、RCE 或完整版本范围。附件中的 JDK 21 standalone 输出、五分支范围、CVSS/CVE 和官方修复状态均未在本稿中独立确认。最有价值的后续工作是在无非回环网络接口的 disposable 环境中完成 Nacos 端到端 marker-only 流程，并对目标 JDK、发行版本和 proposed patch 逐一保留可复核的正负控制。
