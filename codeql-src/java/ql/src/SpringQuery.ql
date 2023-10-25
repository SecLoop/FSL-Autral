/*
	Author: Lousix
	Version: 1.0
*/

import java
import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam

// bindingset[methodName]
// predicate checkAuthByMethod(Method method, string methodName){
// 	methodName != ""
// 	and
// 	method.getACallee().getName().matches(methodName)
// }

// bindingset[annotationName]
// predicate checkAuthByAnnotation(Method method, string annotationName) {
// 	annotationName != ""
// 	and
// 	method.getAnAnnotation().toString() = annotationName
// }

bindingset[methodName, annotationName]
string checkAuth(Method method, string methodName, string annotationName){
	(
		annotationName != ""
		and
		method.getAnAnnotation().toString().matches(annotationName) and result = "backen"
	)
	or
	(	
		methodName != ""
		and
		method.getACallee().getName().matches(methodName) and result = "backen"
	)
	or
	(	methodName != ""
		and
		annotationName != ""
		and
		not method.getAnAnnotation().toString().matches(annotationName) and not method.getACallee().getName().matches(methodName) and result = "front"
	)
}




// from  Class c, Method m, DataFlow::Node source
// where 
// 	m = c.getAMethod() 
// 	and
// 	source instanceof RemoteFlowSource 
// 	and
// 	getControllerFunc(source.getEnclosingCallable()) = m
// 	// and
// 	// m.getName() = "sendSMSByReceiveHumanIDHandler"
// select
//     c,
//     getControllerRoute(c, m) as route,
//     m as method,
// 	// getContentType(m) as contentType,
// 	source,
// 	// getParam(source)
// 	// source.asExpr().(MethodAccess).getMethod()
// 	source.asExpr().(MethodAccess).getMethod(),
// 	source.asExpr().(MethodAccess).getMethod().getQualifiedName()
	


// from Method method
// where method.getACallee().getName().matches("%init%")
// select method


from  Class c, Method m, DataFlow::Node source
where 
	m = c.getAMethod() 
	// // m.getName() = "isLogined"
	and 
	source instanceof RemoteFlowSource 
	and
	getControllerFunc(source.getEnclosingCallable()) = m
	// 与codeqlpy联动的判定标准
	// and
	// source.getEnclosingCallable().getFile().getAbsolutePath() = ""
	// and
	// m.getName() = "isLogined"
select
    c as controller, m as method,
    getControllerRoute(c, m) as route,
	getContentType(m),
	getRequestMethod(m),
	getParam(source) as param,
	source,
	source.getType(),
	getParamAnnotation(source) as annotation,
	getRequestType(source) as request




	// source.getEnclosingCallable().getEnclosingCallable()
	// source.asExpr().getType() as paramtype
	// source.getEnclosingCallable().getFile().getAbsolutePath()