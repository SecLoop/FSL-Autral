/**
 * @name Expression language injection (Spring)
 * @description Evaluation of a user-controlled Spring Expression Language (SpEL) expression
 *              may lead to remote code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id java/spel-expression-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.security.SpelInjectionQuery
import semmle.code.java.dataflow.DataFlow
import SpelInjectionFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from SpelInjectionFlow::PathNode source, SpelInjectionFlow::PathNode sink, Class c, Method m
where SpelInjectionFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "SpelInjection.ql", "SpEL expression depends on a $@.", source.getNode(),
  "user-provided value"
