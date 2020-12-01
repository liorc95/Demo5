package pathTraversal;

import java.io.File;
import javax.servlet.http.HttpServletRequest;

public class PTTest3 {
  private final String BASE_DIRECTORY = "/users/ws/profiles/";

  public void test(HttpServletRequest request, String customDirName) {
    try {
      String fileName = request.getParameter("fileName");
      String dirPath = getValue(BASE_DIRECTORY) + customDirName + "subsubdir/";
      File myFile = new File(dirPath + fileName);
      myFile.delete();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  public String getValue(String str) {
    return str + "userdir/";
  }
}
