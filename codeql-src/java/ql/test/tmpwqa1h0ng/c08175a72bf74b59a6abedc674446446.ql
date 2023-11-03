/**
 * @name Server-side template injection
 * @description Untrusted input interpreted as a template can lead to remote code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id java/server-side-template-injection
 * @tags security
 *       external/cwe/cwe-1336
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.security.TemplateInjectionQuery
import TemplateInjectionFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from TemplateInjectionFlow::PathNode source, TemplateInjectionFlow::PathNode sink, Class c, Method m
where TemplateInjectionFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "TemplateInjection.ql", getParam(source.getNode()), "Template, which may contain code, depends on a $@.",
  source.getNode(), "user-provided value"
