/**
 * @name Hard-coded credential in API call
 * @description Using a hard-coded credential in a call to a sensitive Java API may compromise security.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id java/hardcoded-credential-api-call
 * @tags security
 *       external/cwe/cwe-798
 */

import semmle.code.java.security.HardcodedCredentialsApiCallQuery
import HardcodedCredentialApiCallFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from HardcodedCredentialApiCallFlow::PathNode source, HardcodedCredentialApiCallFlow::PathNode sink, Class c, Method m
where HardcodedCredentialApiCallFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink,"HardcodedCredentialsApiCall.ql", getParam(source.getNode()), "Hard-coded value flows to $@.", sink.getNode(),
  "sensitive API call", source.getNode()
