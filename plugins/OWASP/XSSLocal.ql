/**
 * @name Cross-site scripting from local source
 * @description Writing user input directly to a web page
 *              allows for a cross-site scripting vulnerability.
 * @kind path-problem
 * @problem.severity recommendation
 * @security-severity 6.1
 * @precision medium
 * @id java/xss-local
 * @tags security
 *       external/cwe/cwe-079
 */

import java
import semmle.code.java.security.XssLocalQuery
import XssLocalFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from XssLocalFlow::PathNode source, XssLocalFlow::PathNode sink, Class c, Method m
where XssLocalFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "XSSLocal.ql", "Cross-site scripting vulnerability due to $@.",
  source.getNode(), "user-provided value"
