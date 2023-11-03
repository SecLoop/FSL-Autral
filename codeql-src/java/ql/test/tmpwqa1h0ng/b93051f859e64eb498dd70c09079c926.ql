/**
 * @name OGNL Expression Language statement with user-controlled input
 * @description Evaluation of OGNL Expression Language statement with user-controlled input can
 *                lead to execution of arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/ognl-injection
 * @tags security
 *       external/cwe/cwe-917
 */

import java
import semmle.code.java.security.OgnlInjectionQuery
import OgnlInjectionFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from OgnlInjectionFlow::PathNode source, OgnlInjectionFlow::PathNode sink, Class c, Method m
where OgnlInjectionFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "OgnlInjection.ql", getParam(source.getNode()), "OGNL Expression Language statement depends on a $@.",
  source.getNode(), "user-provided value"
