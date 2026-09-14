# VULN-01 — Spring Cloud Alibaba Nacos XML External Entity (XXE) Disclosure

This repository contains an evidence-based security report and a safe, local-only reproducer for external entity resolution in the XML configuration path of `com.alibaba.cloud:spring-alibaba-nacos-config`.

> Independent research material. It is not an upstream-confirmed advisory or a shipped fix.

| Item | Value |
| --- | --- |
| Upstream project | [`alibaba/spring-cloud-alibaba`](https://github.com/alibaba/spring-cloud-alibaba) |
| Component | `com.alibaba.cloud:spring-alibaba-nacos-config` |
| Primary source baseline | Branch [`2025.1.x`](https://github.com/alibaba/spring-cloud-alibaba/tree/c1b9d60054fb0fe49c752c1b728da76033d7208d), commit `c1b9d60054fb0fe49c752c1b728da76033d7208d`, version `2025.1.0.1-SNAPSHOT` |
| Additional release snapshot | Tag `2025.1.0.0`, commit `09d0a1a7`; a retained artifact-level run is in [`evidence/artifact-parser-client.log`](evidence/artifact-parser-client.log) |
| Assessment date | `2026-09-14` |
| Classification | CWE-611: XML External Entity Reference (XXE) |
| Reproducer | [`poc/XxePoc.java`](poc/XxePoc.java) |
| Secondary language | [中文报告](README.zh-CN.md) |

## Materials and evidence boundary

The supplied `VULN-01-XXE-handoff.md` and `VULN-01-XxePoc.java` were treated as review material, not as instructions. Claims from those files are either independently checked or explicitly labeled as supplied evidence. The public package removes author-machine paths, real credentials, external-network payloads and unverified version or CVE claims. No issue was filed against the upstream repository.

## Executive Summary

If Mallory can create or modify XML content in a Nacos `dataId` that a victim instance loads, and the instance selects the XML configuration path, the content reaches `NacosXmlPropertySourceLoader`. The reviewed implementation constructs a default DOM parser without disabling `DOCTYPE`, external entities, external DTDs, XInclude or external schema access. On a runtime whose default parser resolves external entities, a `file:` entity can become text in the resulting Spring `PropertySource` map.

The demonstrated boundary crossing is remote configuration text causing local file access inside the victim process. This is not a Nacos authentication bypass, session theft or automatic privilege escalation. The narrow demonstrated primitive is local-file content entering the process-local property map; whether an application later exposes that value to Mallory is deployment-specific.

I directly reviewed the `c1b9d60054fb0fe49c752c1b728da76033d7208d` source snapshot, the Nacos-to-loader data path and the `spring.factories` registration. I also ran the repository's sanitized standalone PoC on JDK `21.0.9` on 2026-09-14 using only a temporary marker created by the PoC. A separate retained run record shows the released `2025.1.0.0` artifact placing its self-created marker into a `PropertySource`; that record was inspected, not re-run during this report edit.

This report does not assert a first affected release, a complete branch range, a fixed release, a CVE, a CVSS score or upstream confirmation. Nacos permissions, production prevalence, Spring Boot outer-layer filtering and a full Nacos bootstrap flow remain unverified here.

## Background

### Discovery workflow

The finding was reduced to one concrete question: can attacker-controlled Nacos XML reach a parser that treats external entity declarations as ordinary input and then copy the expanded text into configuration state?

1. Pin a public source snapshot and the released `2025.1.0.0` artifact reference.
2. Search the module for `PropertySourceLoader`, `NacosXmlPropertySourceLoader`, `DocumentBuilderFactory` and `parseNacosData`.
3. Trace the configuration string from Nacos retrieval to `NacosByteArrayResource`, then to the XML loader.
4. Inspect the parser construction for security features and the DOM-to-map sink.
5. Use a marker-only local fixture as a positive control and a hardened parser as a negative control.
6. Keep Nacos transport, authorization and remote disclosure separate from the parser-level proof.

### Reaching the parser

`NacosPropertySourceBuilder.loadNacosData` obtains the configuration (or a local snapshot) and passes it to the parser. The excerpt below is from [`NacosPropertySourceBuilder.java`](https://github.com/alibaba/spring-cloud-alibaba/blob/c1b9d60054fb0fe49c752c1b728da76033d7208d/spring-cloud-alibaba-starters/spring-alibaba-nacos-config/src/main/java/com/alibaba/cloud/nacos/client/NacosPropertySourceBuilder.java#L92-L105):

```java
private List<PropertySource<?>> loadNacosData(String dataId, String group,
        String fileExtension) {
    String data = null;
    try {
        String configSnapshot = NacosSnapshotConfigManager
            .getAndRemoveConfigSnapshot(namespace, dataId, group);
        if (configSnapshot == null) {
            log.debug("get config from nacos, dataId: {}, group: {}", dataId, group);
            data = configService.getConfig(dataId, group, timeout);
        }
        else {
            log.debug("get config from memory snapshot, dataId: {}, group: {}",
                    dataId, group);
            data = configSnapshot;
        }
```

After the empty-data and logging checks, the same method calls the parser (lines 121-122):

```java
return NacosDataParserHandler.getInstance().parseNacosData(dataId, data,
        fileExtension);
```

`NacosDataParserHandler.parseNacosData` preserves the string, selects a loader by extension and wraps the bytes in `NacosByteArrayResource`. The relevant excerpt is from [`NacosDataParserHandler.java`](https://github.com/alibaba/spring-cloud-alibaba/blob/c1b9d60054fb0fe49c752c1b728da76033d7208d/spring-cloud-alibaba-starters/spring-alibaba-nacos-config/src/main/java/com/alibaba/cloud/nacos/parser/NacosDataParserHandler.java#L66-L92):

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
```

The module registers the XML loader in [`spring.factories`](https://github.com/alibaba/spring-cloud-alibaba/blob/c1b9d60054fb0fe49c752c1b728da76033d7208d/spring-cloud-alibaba-starters/spring-alibaba-nacos-config/src/main/resources/META-INF/spring.factories#L3-L5):

```properties
org.springframework.boot.env.PropertySourceLoader=\
com.alibaba.cloud.nacos.parser.NacosJsonPropertySourceLoader,\
com.alibaba.cloud.nacos.parser.NacosXmlPropertySourceLoader
```

The default extension is `properties`; XML is an explicit or dataId-derived choice. `canLoadFileExtension` uses a case-insensitive `endsWith` comparison, which affects reachability but is not the root cause. `getOrder()` returns `Integer.MIN_VALUE`, giving this loader the highest `Ordered` priority.

## Vulnerability Details

### Mallory's controlled input

Mallory only needs to write XML-shaped text to a `dataId` that the victim loads. The public PoC uses a temporary fixture created by the same process:

```xml
<?xml version="1.0"?>
<!DOCTYPE config [
  <!ENTITY localMarker SYSTEM "file://<temporary fixture created by this run>">
]>
<config><leaked>&localMarker;</leaked></config>
```

The fixture contains a harmless marker. The public PoC does not read an existing secret, contact an HTTP/LDAP endpoint or reference cloud metadata.

### Missing parser boundary

The decisive source is [`NacosXmlPropertySourceLoader.java`](https://github.com/alibaba/spring-cloud-alibaba/blob/c1b9d60054fb0fe49c752c1b728da76033d7208d/spring-cloud-alibaba-starters/spring-alibaba-nacos-config/src/main/java/com/alibaba/cloud/nacos/parser/NacosXmlPropertySourceLoader.java#L101-L109), lines 101-109 of the assessed snapshot:

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

There is no intervening `FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl`, external-entity, `ACCESS_EXTERNAL_*`, XInclude or rejecting `EntityResolver` configuration. The source therefore does not guarantee that external entity access is disabled; the exact default behavior still depends on the JAXP provider and runtime.

### From expanded text to configuration state

The same class copies leaf text into a map (see the `parseNodeList` excerpt in the linked source):

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

If the DOM parser expands `&localMarker;`, that value becomes a text node and is stored under `config.leaked`. `doLoad` wraps the map in `OriginTrackedMapPropertySource`. The narrow established impact is therefore file content entering the victim process's property source. A later log, actuator endpoint or business response is not assumed.

### Evidence status

A retained local validation record for `com.alibaba.cloud:spring-alibaba-nacos-config:2025.1.0.0` contains only these identifying lines:

```text
ARTIFACT_PARSER_MARKER=LOCAL_XXE_MARKER_20260908_7F4FEC5C
ARTIFACT_PARSER_RESULT=LOCAL_XXE_MARKER_REACHED_PROPERTY_SOURCE
```

The record supports the artifact-level parser-to-`PropertySource` observation for a self-created marker. It does not establish Nacos write permissions, transport, production prevalence, remote disclosure or a complete release range. The original handoff's standalone output is not treated as an independent observation.

The assessed `2025.1.x` snapshot and `2025.1.0.0` release are evidence points, not a claim that every historical or maintained branch is affected. No upstream fix was verified for this report.

## Exploitability Analysis

### Verified prerequisites

- The application uses the Nacos configuration starter containing `NacosXmlPropertySourceLoader`.
- The configuration selects the XML path, rather than the default `properties` path.
- Mallory can create or modify the relevant `dataId`, or otherwise control the equivalent configuration string. This is an attacker capability prerequisite, not evidence of a Nacos authorization bypass.
- The victim process can read the target file. The public PoC targets only a file created by itself.

Under these conditions, the primitive is external-entity file access followed by insertion into local configuration state. It does not by itself grant root, administrator or Nacos management access, and it is not automatic remote code execution.

### Stronger paths not tested

This report does not execute network URIs, external DTD callbacks, cloud-metadata requests, parameter-entity exfiltration or entity-expansion stress tests, and it does not provide those payloads. SSRF, blind callbacks and denial of service remain conditional risks that depend on the parser provider, network policy and resource limits. Spring Boot outer-layer `DOCTYPE` filtering was not evaluated through a full Nacos deployment.

### Controls and limitations

- **Source checked:** Nacos retrieval, parser selection, loader registration, default DOM construction and map insertion.
- **Current run:** the sanitized repository PoC was compiled and run on JDK `21.0.9` using only a self-created temporary marker; the stable output is recorded in [`evidence/local-poc-run-20260914.txt`](evidence/local-poc-run-20260914.txt).
- **Retained supplied record:** the release-artifact marker output in [`evidence/artifact-parser-client.log`](evidence/artifact-parser-client.log) was inspected but not re-run during this report edit.
- **Not completed:** full Nacos server plus victim bootstrap, JDK/branch matrix, authorization model, remote reflection and production reliability.
- **Not claimed:** a CVE/CVSS, a complete affected range, a fixed version, root/RCE, or upstream confirmation.

## Proof of Concept

### Design and safety boundary

[`poc/XxePoc.java`](poc/XxePoc.java) is a dependency-free Java program that:

1. Creates a temporary directory and writes `CONTROLLED-LOCAL-SECRET` to a fixture it owns.
2. Places only that fixture URI in a `DOCTYPE` external entity.
3. Parses the bytes with a mirror of the reviewed vulnerable construction and prints `config.leaked`.
4. Parses the same bytes with the proposed hardened construction and prints the rejection.
5. Deletes the fixture and directory in `finally`.

It never starts Nacos, sends network traffic, reads a pre-existing file or changes system state outside its temporary fixture.

### Run it

From the repository root:

```sh
cd poc
javac XxePoc.java
java XxePoc
```

PowerShell:

```powershell
Set-Location poc
javac .\XxePoc.java
java XxePoc
```

### Observed result

On 2026-09-14, I ran the repository PoC with JDK `21.0.9`. The stable standard output was:

```text
fixture=created-by-this-process
unhardened.config.leaked=CONTROLLED-LOCAL-SECRET
hardened=rejected (IOException)
```

This run demonstrates the parser and map sinks with a self-created marker. JAXP also wrote a locale-dependent diagnostic to stderr; it is intentionally omitted from the portable record. A runtime that rejects the un-hardened parser by default would show a different result and would require separate validation.

### Full Nacos flow

A complete Nacos transport/bootstrap reproduction needs a tightly isolated disposable environment and an XML-configured victim application. That flow was not completed here, so this repository does not publish fabricated Nacos write commands, responses, logs or actuator output. The parser-level proof should not be read as proof of Nacos authorization, remote reflection or production deployment prevalence.

## Remediation

### Proposed source-compatible fix

Create the `DocumentBuilder` with fail-closed security controls and do not silently fall back to the insecure provider defaults:

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

Replace the unprotected construction in `parseXml2Map`, and preserve the original parsing exception rather than `e.getCause()`:

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

This is a proposed remediation, not an upstream-shipped fix. Rejecting `DOCTYPE` intentionally changes compatibility for XML documents that use DTDs; that behavior should be confirmed with the product maintainers rather than silently re-enabling external access.

### Regression coverage

At the real `load` entry point, add tests for:

- ordinary XML node and attribute values still loading;
- a `DOCTYPE` plus a local marker entity raising `IOException` with the SAX cause preserved;
- XInclude content not entering the property map;
- extension-selection behavior remaining unchanged;
- unsupported security controls failing closed instead of falling back to the default parser.

A separate isolated integration test should cover Nacos fetch, refresh and error handling without reading host secrets or contacting non-loopback addresses. No such integration test is claimed as passed here.

## Summary

The assessed `c1b9d60054fb0fe49c752c1b728da76033d7208d` source sends selected Nacos configuration text through `NacosDataParserHandler` into `NacosXmlPropertySourceLoader`, which constructs an un-hardened DOM parser and copies expanded leaf text into a Spring `PropertySource`. When Mallory can control the XML `dataId` and the runtime resolves external entities, a local file's content can enter that process-local configuration map.

The repository contains a safe local PoC with an actual JDK `21.0.9` run, plus a separately labeled retained artifact-level record. Those materials do not prove Nacos authorization bypass, remote reflection, SSRF, denial of service, RCE, a complete affected-version range or an upstream-confirmed fix. The most useful next validation is a marker-only end-to-end test inside a network-isolated disposable environment, followed by release-by-release and proposed-fix regression checks.
