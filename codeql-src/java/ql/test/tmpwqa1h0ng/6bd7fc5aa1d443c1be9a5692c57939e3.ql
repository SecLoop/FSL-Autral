/**
 * @name Query built from local-user-controlled sources
 * @description Building a SQL or Java Persistence query from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity recommendation
 * @security-severity 8.8
 * @precision medium
 * @id java/sql-injection-local
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-564
 */

import java
import semmle.code.java.security.SqlTaintedLocalQuery
import LocalUserInputToQueryInjectionFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from
  LocalUserInputToQueryInjectionFlow::PathNode source,
  LocalUserInputToQueryInjectionFlow::PathNode sink, Class c, Method m
where LocalUserInputToQueryInjectionFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "SqlTaintedLocal.ql", getParam(source.getNode()), "This query depends on a $@.", source.getNode(),
  "user-provided value"
