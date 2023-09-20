/**
 * @name XSLT transformation with user-controlled stylesheet
 * @description Performing an XSLT transformation with user-controlled stylesheets can lead to
 *              information disclosure or execution of arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/xslt-injection
 * @tags security
 *       external/cwe/cwe-074
 */

import java
import semmle.code.java.security.XsltInjectionQuery
import XsltInjectionFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from XsltInjectionFlow::PathNode source, XsltInjectionFlow::PathNode sink, Class c, Method m
where XsltInjectionFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "XsltInjection.ql", "XSLT transformation might include stylesheet from $@.",
  source.getNode(), "this user input"
