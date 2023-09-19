// /*
// 	Author: Lousix
// 	Version: 2.0
// */

// import java
// import semmle.code.java.dataflow.FlowSources
// private import semmle.code.java.dataflow.ExternalFlow
// import SpringRelated.SpringController // 此处注意import的文件路径

// from  Class c, Method m
// where 
// 	m = c.getAMethod() 
// select
//     c as controller, m as method,
//     getControllerRoute(c, m) as route,
// 	// getContentType(m),
// 	getRequestMethod(m)


/*
	Author: Lousix
	Version: 1.0
*/

import java
import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.dataflow.ExternalFlow
import SpringRelated.SpringController
import SpringRelated.SpringParam


from  Class c, Method m, DataFlow::Node source
where 
	m = c.getAMethod() 
	and 
	source instanceof RemoteFlowSource 
	and
	getControllerFunc(source.getEnclosingCallable()) = m
	// 与codeqlpy联动的判定标准
	// and
	// source.getEnclosingCallable().getFile().getAbsolutePath() = ""
	// and
	// m.getName() = "isLogined"
// select
//     c as controller, m as method,
//     getControllerRoute(c, m) as route,
// 		getContentType(m),
// 		getRequestMethod(m),
// 		getParam(source) as param,
// 		source.getType(),
// 	  getParamAnnotation(source) as annotation
select
    c as controller, m as method,
    getControllerRoute(c, m) as route,
	getContentType(m),
	getRequestMethod(m),
	getParam(source) as param,
	source.getType(),
	getParamAnnotation(source) as annotation,
	getRequestType(source) as request