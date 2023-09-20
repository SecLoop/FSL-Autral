/**
 * @id java/android/arbitrary-apk-installation
 * @name Android APK installation
 * @description Creating an intent with a URI pointing to a untrusted file can lead to the installation of an untrusted application.
 * @kind path-problem
 * @security-severity 9.3
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.security.ArbitraryApkInstallationQuery
import ApkInstallationFlow::PathGraph
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

from ApkInstallationFlow::PathNode source, ApkInstallationFlow::PathNode sink, Class c, Method m
where ApkInstallationFlow::flowPath(source, sink)
and
m = c.getAMethod() 
and
getControllerFunc(source.getNode().getEnclosingCallable()) = m
select c, m, source, sink, "ArbitraryApkInstallation.ql", sink.getNode(),"Arbitrary Android APK installation."
