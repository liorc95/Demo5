package pathTraversal;

import java.io.File;
import javax.servlet.http.HttpServletRequest;

public class PTTest2 {
  private final String BASE_DIRECTORY = "/users/ws/profiles/";

  public void test(HttpServletRequest request) {
    String fileName = request.getParameter("fileName");
    sink(fileName);
  }

  private void sink(String filename) {
    File myFile = new File(BASE_DIRECTORY, filename);
    myFile.delete();
  }
}
