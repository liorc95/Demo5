package xee;

import java.io.StringReader;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class XEE1 {

  public String getXml(HttpServletRequest request) {
    String xmlStr = request.getParameter("xml");
    Document doc = unsafe(xmlStr);

    if (doc != null) {
      return doc.getElementsByTagName("foo").item(0).getTextContent();
    } else {
      return "XML error";
    }
  }

  private Document unsafe(String xmlString) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder;
    try {
      builder = factory.newDocumentBuilder();
      return builder.parse(new InputSource(new StringReader(xmlString)));

    } catch (Exception e) {
      e.printStackTrace();
    }

    return null;
  }
}
