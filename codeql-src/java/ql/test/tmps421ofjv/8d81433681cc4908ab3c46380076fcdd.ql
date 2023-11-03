/**
 * @name Hard-coded credential in sensitive call
 * @description Using a hard-coded credential in a sensitive call may compromise security.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision low
 * @id java/hardcoded-credential-sensitive-call
 * @tags security
 *       external/cwe/cwe-798
 */

import java
import semmle.code.java.security.HardcodedCredentialsSourceCallQuery
import HardcodedCredentialSourceCallFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from
  HardcodedCredentialSourceCallFlow::PathNode source,
  HardcodedCredentialSourceCallFlow::PathNode sink, Class c, Method m
where HardcodedCredentialSourceCallFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "HardcodedCredentialsSourceCall.ql", getParam(source), "Hard-coded value flows to $@.", sink.getNode(),
  "sensitive call", source.getNode()
