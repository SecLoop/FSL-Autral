/**
 * @name Local-user-controlled command line
 * @description Using externally controlled strings in a command line is vulnerable to malicious
 *              changes in the strings.
 * @kind path-problem
 * @problem.severity recommendation
 * @security-severity 9.8
 * @precision medium
 * @id java/command-line-injection-local
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import java
import semmle.code.java.security.CommandLineQuery
import semmle.code.java.security.ExternalProcess
import LocalUserInputToArgumentToExecFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from
  LocalUserInputToArgumentToExecFlow::PathNode source,
  LocalUserInputToArgumentToExecFlow::PathNode sink, Expr e, Class c, Method m
where
  LocalUserInputToArgumentToExecFlow::flowPath(source, sink) and
  argumentToExec(e, sink.getNode())
  and
  m = c.getAMethod() 
  and
  getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "ExecTaintedLocal.ql", "This command line depends on a $@.", source.getNode(),
  "user-provided value","ExecTaintedLocal.ql",e
