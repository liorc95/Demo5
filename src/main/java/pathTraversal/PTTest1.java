package pathTraversal;

import java.io.File;
import javax.servlet.http.HttpServletRequest;

// Base Directory: /users/ws/profiles/
// Unsafe filename: ../../../etc/passwd
// Canonical unsafe-file: /users/ws/profiles/../../../etc/passwd ----->>>  /etc/passwd ---->>>>
// Vulnerability!

public class PTTest1 {
  private final String BASE_DIRECTORY = "/users/ws/profiles/";

  public void test(HttpServletRequest request) {
    try {
      String fileName = request.getParameter("fileName");
      File myFile = new File(BASE_DIRECTORY + fileName);
      deleteFile(myFile);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  private void deleteFile(File f) {
    f.delete();
  }
}
