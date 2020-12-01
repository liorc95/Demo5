package ldap;

import org.owasp.encoder.Encode;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

public class LDAPTest3 {

  public boolean test(HttpServletRequest request, DirContext ctx) throws NamingException {
    String userUnsafe = null;
    String pass = request.getParameter("pass");
    String user = request.getParameter("user");
    userUnsafe = user;
    user = "{0}" + "_USER";

    String filter = "(&(uid=" + user + ")(userPassword=" + "{1}" + "))";

    NamingEnumeration<SearchResult> results =
        ctx.search("ou=system", filter, new String[] {userUnsafe, pass}, new SearchControls());
    return results.hasMore();
  }
}