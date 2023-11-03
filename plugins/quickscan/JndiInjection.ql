/**
 * @name JNDI lookup with user-controlled name
 * @description Performing a JNDI lookup with a user-controlled name can lead to the download of an untrusted
 *              object and to execution of arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/jndi-injection
 * @tags security
 *       external/cwe/cwe-074
 */

import java
import semmle.code.java.security.JndiInjectionQuery
import JndiInjectionFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from JndiInjectionFlow::PathNode source, JndiInjectionFlow::PathNode sink, Class c, Method m
where JndiInjectionFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "JndiInjection.ql", "JNDI lookup might include name from $@.", source.getNode(),
  "this user input", sink.getNode()
