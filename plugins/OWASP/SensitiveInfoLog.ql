/**
 * @name Insertion of sensitive information into log files
 * @description Writing sensitive information to log files can allow that
 *              information to be leaked to an attacker more easily.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/sensitive-log
 * @tags security
 *       external/cwe/cwe-532
 */

import java
import semmle.code.java.security.SensitiveLoggingQuery
import SensitiveLoggerFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from SensitiveLoggerFlow::PathNode source, SensitiveLoggerFlow::PathNode sink,Class c, Method m
where SensitiveLoggerFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "SensitiveInfoLog.ql", "This $@ is written to a log file.", source.getNode(),
  "potentially sensitive information"
