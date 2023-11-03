/**
 * @name LDAP query built from user-controlled sources
 * @description Building an LDAP query from user-controlled sources is vulnerable to insertion of
 *              malicious LDAP code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/ldap-injection
 * @tags security
 *       external/cwe/cwe-090
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.LdapInjectionQuery
import LdapInjectionFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from LdapInjectionFlow::PathNode source, LdapInjectionFlow::PathNode sink, Class c, Method m
where LdapInjectionFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "LdapInjection.ql", "This LDAP query depends on a $@.", source.getNode(),
  "user-provided value"
