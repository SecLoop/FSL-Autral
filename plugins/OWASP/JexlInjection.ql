/**
 * @name Expression language injection (JEXL)
 * @description Evaluation of a user-controlled JEXL expression
 *              may lead to arbitrary code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id java/jexl-expression-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.security.JexlInjectionQuery
import JexlInjectionFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from JexlInjectionFlow::PathNode source, JexlInjectionFlow::PathNode sink, Class c, Method m
where JexlInjectionFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select  c, m, source, sink,"JexlInjection.ql", "JEXL expression depends on a $@.", source.getNode(),
  "user-provided value", sink.getNode()
