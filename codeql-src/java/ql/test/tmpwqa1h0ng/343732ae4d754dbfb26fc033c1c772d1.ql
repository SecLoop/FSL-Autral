/**
 * @name Groovy Language injection
 * @description Evaluation of a user-controlled Groovy script
 *              may lead to arbitrary code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id java/groovy-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.security.GroovyInjectionQuery
import GroovyInjectionFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from GroovyInjectionFlow::PathNode source, GroovyInjectionFlow::PathNode sink, Class c, Method m
where GroovyInjectionFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select  c, m, source, sink, "GroovyInjection.ql", getParam(source.getNode()), "Groovy script depends on a $@.", source.getNode(),
  "user-provided value",sink.getNode()
