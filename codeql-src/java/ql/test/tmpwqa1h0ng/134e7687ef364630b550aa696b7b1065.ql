/**
 * @name Uncontrolled command line
 * @description Using externally controlled strings in a command line is vulnerable to malicious
 *              changes in the strings.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/command-line-injection
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import java
import semmle.code.java.security.CommandLineQuery
import RemoteUserInputToArgumentToExecFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from
  RemoteUserInputToArgumentToExecFlow::PathNode source,
  RemoteUserInputToArgumentToExecFlow::PathNode sink, Expr execArg,Class c, Method m
where execIsTainted(source, sink, execArg)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "ExecTainted.ql", getParam(source.getNode()), "This command line depends on a $@.", source.getNode(),
  "user-provided value",execArg
