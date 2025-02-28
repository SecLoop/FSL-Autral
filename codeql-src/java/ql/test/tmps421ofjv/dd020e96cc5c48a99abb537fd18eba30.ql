/**
 * @name Partial path traversal vulnerability from remote
 * @description A prefix used to check that a canonicalised path falls within another must be slash-terminated.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id java/partial-path-traversal-from-remote
 * @tags security
 *       external/cwe/cwe-023
 */

import semmle.code.java.security.PartialPathTraversalQuery
import PartialPathTraversalFromRemoteFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from
  PartialPathTraversalFromRemoteFlow::PathNode source,
  PartialPathTraversalFromRemoteFlow::PathNode sink, Class c, Method m
where PartialPathTraversalFromRemoteFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "PartialPathTraversalFromRemote.ql", getParam(source), 
  "Partial Path Traversal Vulnerability due to insufficient guard against path traversal from $@.",
  source, "user-supplied data"
