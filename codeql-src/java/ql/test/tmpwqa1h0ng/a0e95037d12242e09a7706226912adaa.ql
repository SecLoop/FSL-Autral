/**
 * @name XPath injection
 * @description Building an XPath expression from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/xml/xpath-injection
 * @tags security
 *       external/cwe/cwe-643
 */

import java
import semmle.code.java.security.XPathInjectionQuery
import XPathInjectionFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from XPathInjectionFlow::PathNode source, XPathInjectionFlow::PathNode sink, Class c, Method m
where XPathInjectionFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "XPathInjection.ql", getParam(source.getNode()), "XPath expression depends on a $@.", source.getNode(),
  "user-provided value"
