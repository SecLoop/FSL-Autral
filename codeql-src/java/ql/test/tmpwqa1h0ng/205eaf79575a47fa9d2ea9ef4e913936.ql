/**
 * @name Server-side request forgery
 * @description Making web requests based on unvalidated user-input
 *              may cause the server to communicate with malicious servers.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id java/ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import java
import semmle.code.java.security.RequestForgeryConfig
import RequestForgeryFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from RequestForgeryFlow::PathNode source, RequestForgeryFlow::PathNode sink, Class c, Method m
where RequestForgeryFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "RequestForgery.ql", getParam(source.getNode()), "Potential server-side request forgery due to a $@.",
  source.getNode(), "user-provided value"
