/**
 * @name Untrusted data passed to external API
 * @description Data provided remotely is used in this external API without sanitization, which could be a security risk.
 * @id java/untrusted-data-to-external-api
 * @kind path-problem
 * @precision low
 * @problem.severity error
 * @security-severity 7.8
 * @tags security external/cwe/cwe-20
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.ExternalAPIs
import UntrustedDataToExternalApiFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from UntrustedDataToExternalApiFlow::PathNode source, UntrustedDataToExternalApiFlow::PathNode sink, Class c, Method m
where UntrustedDataToExternalApiFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "UntrustedDataToExternalAPI.ql",
  "Call to " + sink.getNode().(ExternalApiDataNode).getMethodDescription() +
    " with untrusted data from $@.", source, source.toString()
