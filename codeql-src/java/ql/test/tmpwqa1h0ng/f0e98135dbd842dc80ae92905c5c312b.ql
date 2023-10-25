/**
 * @name Expression language injection (MVEL)
 * @description Evaluation of a user-controlled MVEL expression
 *              may lead to remote code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id java/mvel-expression-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.security.MvelInjectionQuery
import MvelInjectionFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from MvelInjectionFlow::PathNode source, MvelInjectionFlow::PathNode sink, Class c, Method m
where MvelInjectionFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "MvelInjection.ql", getParam(source.getNode()), "MVEL expression depends on a $@.", source.getNode(),
  "user-provided value"
